# Copyright (C) 2010 Pythonheads, all rights reserved.
# -*- coding: utf-8 -*-

'''
A single module pythonic iDeal module.

'''

import logging
import time
import re
import urllib2
import base64
import tempfile
import subprocess
import M2Crypto

from lxml import etree
from lxml.etree import Element
from lxml.builder import E
from cStringIO import StringIO

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

ENCODING = 'utf-8'

XMLSIG_TEMPLATE="""<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  <Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue></DigestValue></Reference></SignedInfo><SignatureValue/>
  <KeyInfo><KeyName></KeyName></KeyInfo></Signature>"""


### Exceptions ###

class IDealException(Exception): pass

class IDealConfigException(IDealException): pass

class IDealErrorRes(IDealException):
    '''An error response returned by the acquirer'''
    def __init__(self, error_code, error_message, error_detail, consumer_message):
        self.error_code = error_code
        self.error_message = error_message
        self.error_detail = error_detail
        self.consumer_message = consumer_message
        summary = '%s: %s (%s)' % (error_code, error_message, error_detail)
        super(IDealException, self).__init__(summary)

### Security objects ###

class Cert(object):
    def __init__(self, path):
        self.path = path
        self.cert = M2Crypto.X509.load_cert(path)

    def get_fingerprint(self):
        return self.cert.get_fingerprint('sha1').zfill(40)
        
class Pem(object):
    def __init__(self, path, passwd):
        self.path = path
        self.passwd = passwd
    
### Objects used in requests & responses ###

class Issuer(object):
    def __init__(self, id, list_type, name):
        self.id = id
        self.list_type = list_type
        self.name = name

class AcquirerTrxRes(object):
    def __init__(self, acquirer_id, issuer_authentication_url, transaction_id, purchase_id):
        self.acquirer_id = acquirer_id
        self.issuer_authentication_url = issuer_authentication_url
        self.transaction_id = transaction_id
        self.purchase_id = purchase_id

class AcquirerStatusRes(object):
    STATUS_CODES = ['Success', 'Cancelled', 'Expired', 'Failure', 'Open']

    def __init__(self, acquirer_id, transaction_id, status, consumer_name,
                 consumer_iban, consumer_bic, consumer_city=None):
        self.acquirer_id = acquirer_id
        self.transaction_id = transaction_id
        self.status = status
        self.consumer_name = consumer_name
        self.consumer_iban = consumer_iban
        self.consumer_account_number = consumer_iban
        self.consumer_bic = consumer_bic
        self.consumer_city = consumer_city

        if self.status not in self.STATUS_CODES:
            raise IDealException('Unknown status code %s' % (self.status_code))

    def is_open(self):
        return self.status == 'Open'

    def is_success(self):
        return self.status == 'Success'

    def is_failed(self):
        return self.status in ['Expired', 'Failure', 'Cancelled']

    def is_cancelled(self):
        return self.status == 'Cancelled'

class Acquirer(object):
    def __init__(self, endpoint, cert):
        self.endpoint = endpoint
        self.cert = cert

    def do_request(self, request):
        '''Post an XML message to iDeal, verify the response and check
        for errors.'''
        tmp = tempfile.NamedTemporaryFile()

        request_xml = request.to_xml()
        request_xml.append(etree.fromstring(XMLSIG_TEMPLATE))

        data = etree.tostring(
                request_xml,
                pretty_print=True,
                xml_declaration=True,
                encoding=ENCODING)

        tmp.write(data)
        tmp.flush()

        data = subprocess.check_output(
                ['xmlsec1', 'sign',
                    '--privkey-pem:'+ request.merchant.cert.get_fingerprint(),
                        request.merchant.pem.path,
                    '--pwd', request.merchant.pem.passwd,
                    tmp.name])

        log.debug('write: %s', data)

        # Call the server
        url = re.sub('^ssl://', 'https://', self.endpoint)
        req = urllib2.Request(url=url, data=data)
        res = urllib2.urlopen(req)
        tmp.seek(0)
        tmp.truncate()
        tmp.write(res.read())
        tmp.flush()
        tmp.seek(0)
        body = tmp.read()
        res.close()
        log.debug('read: %s', body)

        try:
            subprocess.check_output(
                ['xmlsec1', 'verify',
                    '--pubkey-cert-pem', self.cert.path,
                    '--print-debug',
                    tmp.name],
                stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as output:
            raise IDealException, output


        # Get rid of the namespace (or we'll have to suppyl it every time)
        # and parse the response 
        body = re.sub('xmlns=[\'"].+?[\'"]', '', body)      
        xml = etree.parse(StringIO(body))
        
        # Check for errors, this means getting either an error response or
        # a response without an acquirer ID.
        if xml.xpath('/*/Error'):
            raise IDealErrorRes(
                error_code=xml.xpath('//Error/errorCode/child::text()')[0],
                error_message=xml.xpath('//Error/errorMessage/child::text()')[0],
                error_detail=xml.xpath('//Error/errorDetail/child::text()')[0],
                consumer_message=xml.xpath('//Error/consumerMessage/child::text()')[0])
        elif not xml.xpath('//Acquirer/acquirerID'):
            raise IDealException('No acquirer id in response')

        return xml

class Merchant(object):
    '''
    A merchant with its ids and credentials
    
    '''
    def __init__(self, merchant_id, sub_id, cert, pem):
        self.merchant_id = merchant_id
        self.sub_id = sub_id        
        self.cert = cert
        self.pem = pem

    def to_xml(self):
        return E.Merchant(
            E.merchantID(self.merchant_id),
            E.subID(self.sub_id))

### Actual requests ###

class Request(object):
    def __init__(self, request_type, merchant):
        self.request_type = request_type
        self.merchant = merchant
    
    def to_xml(self):       
        '''Convert this request to XML.'''
        timestamp = self._get_iso_timestamp()
        
        request = Element(
                self.request_type,
                version="3.3.1",
                xmlns="http://www.idealdesk.com/ideal/messages/mer-acq/3.3.1",
                )
        request.append(E.createDateTimestamp(timestamp))
        request.append(self.merchant.to_xml()) 
        return request

    def _get_iso_timestamp(self):
        '''Get a timestamp in ISO format''' 
        return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    
class DirectoryReq(Request):

    def __init__(self, merchant):
        super(DirectoryReq, self).__init__('DirectoryReq', merchant)
    
class AcquirerTrxReq(Request):

    def __init__(self, merchant, issuer_id, purchase_id, amount, description, 
                  entrance_code, expiration_period, merchant_return_url):
        super(AcquirerTrxReq, self).__init__('AcquirerTrxReq', merchant)
        self.issuer_id = issuer_id
        self.purchase_id = purchase_id
        self.amount = amount
        self.description = description
        self.entrance_code = entrance_code
        self.expiration_period = expiration_period
        self.merchant_return_url = merchant_return_url
        self.currency = 'EUR'
        self.language = 'nl'
    
    def to_xml(self):
        request = super(AcquirerTrxReq, self).to_xml()      
        request.insert(1,
            E.Issuer(
                E.issuerID(self.issuer_id)
            )
        )
        request.append(
            E.Transaction(
                E.purchaseID(self.purchase_id),
                E.amount(self.amount),
                E.currency(self.currency),
                E.expirationPeriod(self.expiration_period),
                E.language(self.language),
                E.description(self.description),
                E.entranceCode(self.entrance_code)
            )
        )
        request.find('Merchant').append(
            E.merchantReturnURL(self.merchant_return_url))
        return request
    
class AcquirerStatusReq(Request):
    def __init__(self, merchant, transaction_id):
        super(AcquirerStatusReq, self).__init__('AcquirerStatusReq', merchant)
        self.transaction_id = transaction_id

    def to_xml(self):
        request = super(AcquirerStatusReq, self).to_xml()       
        request.append(E.Transaction(E.transactionID(self.transaction_id))) 
        return request

### The actual connector ###

class IDEALConnector(object):
    '''A Pythonic iDeal connector'''
    
    def __init__(self, merchant, acquirer):
        self.merchant = merchant
        self.acquirer = acquirer

    def get_issuer_list(self):
        response = self.acquirer.do_request(DirectoryReq(self.merchant))
        issuers = []
        for issuer in response.xpath('Directory/Country/Issuer'):
            if issuer.tag == 'Issuer':
                issuers.append(
                    Issuer(
                        id=unicode(issuer.xpath('issuerID/child::text()')[0]),
                        name=unicode(
                            issuer.xpath('issuerName/child::text()')[0]),
                        list_type=unicode(
                            issuer.xpath(
                                'parent::node()/countryNames/child::text()')[0])
                        )
                    )
        return issuers


    def request_transaction(self, issuer_id, purchase_id, amount, 
                            description, entrance_code, 
                            return_url, expiration_period=None):
        '''Request to make a transaction'''
        expiration_period = expiration_period or 'PT10M'
        response = self.acquirer.do_request(
            AcquirerTrxReq(self.merchant, issuer_id, purchase_id, amount, description, 
                           entrance_code, expiration_period, return_url))
        
        return AcquirerTrxRes(
            acquirer_id = unicode(
                response.xpath(
                    '/AcquirerTrxRes/Acquirer/acquirerID/child::text()')[0]),
            issuer_authentication_url = unicode(
                response.xpath(
                    '/AcquirerTrxRes/Issuer/issuerAuthenticationURL/'
                    'child::text()')[0]),
            transaction_id = unicode(
                response.xpath(
                    '/AcquirerTrxRes/Transaction/transactionID/'
                    'child::text()')[0]),
            purchase_id = unicode(
                response.xpath(
                    '/AcquirerTrxRes/Transaction/purchaseID/child::text()')[0]))
    
    def request_transaction_status(self, transaction_id):
        '''Request the status of a transaction'''
        response = self.acquirer.do_request(AcquirerStatusReq(
            self.merchant, transaction_id))
        
        timestamp = unicode(
                response.xpath(
                    '/AcquirerStatusRes/createDateTimestamp/child::text()')[0])
        acquirer_id = unicode(
                response.xpath(
                    '/AcquirerStatusRes/Acquirer/acquirerID/child::text()')[0])
        transaction_id = unicode(
                response.xpath(
                    '/AcquirerStatusRes/Transaction/transactionID/'
                    'child::text()')[0])
        status = unicode(
                response.xpath(
                    '/AcquirerStatusRes/Transaction/status/child::text()')[0])
        if status == 'Success':     
            consumer_name = unicode(
                response.xpath(
                        '/AcquirerStatusRes/Transaction/consumerName/'
                        'child::text()')[0])
            consumer_iban = response.xpath(
                        '/AcquirerStatusRes/Transaction/consumerIBAN/'
                        'child::text()')[0]
            consumer_bic = unicode(
                    response.xpath('/AcquirerStatusRes/Transaction/consumerBIC/'
                        'child::text()')[0])
        else:
            consumer_name, consumer_iban, consumer_bic = None, None, None
            
        return AcquirerStatusRes(acquirer_id=acquirer_id,
                                 transaction_id=transaction_id,
                                 status=status,
                                 consumer_name=consumer_name,
                                 consumer_iban=consumer_iban,
                                 consumer_bic=consumer_bic,
                                 consumer_city=None)
         
