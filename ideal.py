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

from collections import namedtuple
import M2Crypto.EVP
from lxml import etree
from lxml.etree import Element
from lxml.builder import E
from cStringIO import StringIO

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

ENCODING = 'utf-8'

Issuer = namedtuple('Issuer', 'id list_type name')
AcquirerTrxRes = namedtuple('AcquirerTrxRes', 'acquirer_id issuer_authentication_url transaction_id purchase_id')
AcquirerStatusRes = namedtuple('AcquirerStatusRes', 'acquirer_id transaction_id status consumer_name consumer_account_number consumer_city')

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

class Cert(object):
    def __init__(self, path):
        self.cert = M2Crypto.X509.load_cert(path)
        
    def get_fingerprint(self):
        return self.cert.get_fingerprint('sha1').zfill(40)

    def verify_signature(self, signature, message):
        """Verify an aquirer message signature"""               
        pubkey = self.cert.get_pubkey()
        pubkey.verify_init()
        pubkey.verify_update(message.encode(ENCODING))
        return pubkey.verify_final(signature)

class Pem(object):
    def __init__(self, path, passwd):
        self.pkey = M2Crypto.EVP.load_key(path, lambda x: passwd)
    
    def sign(self, message):
        '''Create an iDeal signature for the specified message'''
        # Encoding is important because signing is a binary operation and will 
        # produce different results based on the encoding
        message = message.encode(ENCODING)      
        self.pkey.sign_init()
        self.pkey.sign_update(message)
        signature = self.pkey.final()       
        return signature

    def get_tokencode(self, *args):
        '''Get the base64 encoded tokencode'''
        gist = re.sub(' |\t|\n', '', ''.join([unicode(s) for s in args]))       
        log.debug('gist is: %s', gist)
        return base64.b64encode(self.sign(gist))

class Acquirer(object):
    def __init__(self, endpoint, cert):
        self.endpoint = endpoint
        self.cert = cert

    def verify_message(self, fingerprint, signature, args):
        '''Ensure a response signature is valid'''
        if not fingerprint == self.cert.get_fingerprint():
            raise IDealException('Unexpected certificate fingerprint')      
        gist = re.sub(' |\t|\n', '', ''.join([unicode(s) for s in args]))
        signature = base64.b64decode(signature)
        return bool(self.cert.verify_signature(signature, gist))
    
    def do_request(self, request):
        '''Post an XML message to iDeal and check the response for errors.'''   
            
        # Since iDeal does not actually seem to use an xml parser on the server 
        # side, some strings (like the xml preamble) have to be manually 
        # specified.        
        data = etree.tostring(request.to_xml(), pretty_print=True, encoding=ENCODING) # xml_declaration=True)       
        data = '<?xml version="1.0" encoding="UTF-8"?>\n' + data
        log.debug('write: %s', data)
        
        # Call the server
        url = re.sub('^ssl://', 'https://', self.endpoint)
        req = urllib2.Request(url=url, data=data)
        res = urllib2.urlopen(req)
        body = res.read()
        res.close()
        log.debug('read: %s', body)
                
        # Get rid of the namespace (or we'll have to suppyl it every time)
        # and parse the response 
        body = re.sub('xmlns=[\'"].+?[\'"]', '', body)      
        xml = etree.parse(StringIO(body))
        
        # Check for errors, this means getting either an error response or
        # a response without an acquirer ID.
        if xml.xpath('/ErrorRes'):
            raise IDealErrorRes(
                error_code=xml.xpath('/ErrorRes/Error/errorCode/child::text()')[0],
                error_message=xml.xpath('/ErrorRes/Error/errorMessage/child::text()')[0],
                error_detail=xml.xpath('/ErrorRes/Error/errorDetail/child::text()')[0],
                consumer_message=xml.xpath('/ErrorRes/Error/consumerMessage/child::text()')[0])
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
        self.cer = cert
        self.pem = pem

    def to_xml(self, sign_values):
        return E.Merchant(
            E.merchantID(self.merchant_id),
            E.subID(self.sub_id),
            E.authentication('SHA1_RSA'),
            E.token(self.cer.get_fingerprint()),
            E.tokenCode(self.pem.get_tokencode(*sign_values)))

class Request(object):
    def __init__(self, request_type, merchant):
        self.request_type = request_type
        self.merchant = merchant
    
    def get_sign_values(self, timestamp):
        '''Get the values used for signing this request.'''
        raise NotImplemented()
    
    def to_xml(self):       
        '''Convert this request to XML.'''
        timestamp = self._get_iso_timestamp()
        sign_values = self.get_sign_values(timestamp)       
        log.debug('Sign using %s', sign_values)
        
        request = Element(self.request_type,
                          version="1.1.0",
                          xmlns="http://www.idealdesk.com/Message")
        request.append(E.createDateTimeStamp(timestamp))
        request.append(self.merchant.to_xml(sign_values))       
        return request

    def _get_iso_timestamp(self):
        '''Get a timestamp in ISO format''' 
        return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    
class DirectoryReq(Request):

    def __init__(self, merchant):
        super(DirectoryReq, self).__init__('DirectoryReq', merchant)
    
    def get_sign_values(self, timestamp):
        return [timestamp, self.merchant.merchant_id, self.merchant.sub_id] 

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
    
    def get_sign_values(self, timestamp):
        return [timestamp, self.issuer_id, self.merchant.merchant_id, 
                self.merchant.sub_id, self.merchant_return_url,
                self.purchase_id, self.amount, self.currency, self.language,
                self.description, self.entrance_code]

    def to_xml(self):
        request = super(AcquirerTrxReq, self).to_xml()      
        request.append(
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

    def get_sign_values(self, timestamp):       
        return [timestamp, self.merchant.merchant_id, self.merchant.sub_id, self.transaction_id]

    def to_xml(self):
        request = super(AcquirerStatusReq, self).to_xml()       
        request.append(E.Transaction(E.transactionID(self.transaction_id))) 
        return request

class IDEALConnector(object):
    '''A Pythonic iDeal connector'''
    
    def __init__(self, merchant, acquirer):
        self.merchant = merchant
        self.acquirer = acquirer

    def get_issuer_list(self):
        response = self.acquirer.do_request(DirectoryReq(self.merchant))                
        issuers = []
        for issuer in response.xpath('Directory/Issuer'):
            if issuer.tag == 'Issuer':
                issuers += [Issuer(id=issuer.xpath('issuerID/child::text()')[0],
                                   name=issuer.xpath('issuerName/child::text()')[0],
                                   list_type=issuer.xpath('issuerList/child::text()')[0]),]
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
            acquirer_id=response.xpath('/AcquirerTrxRes/Acquirer/acquirerID/child::text()')[0],
            issuer_authentication_url=response.xpath('/AcquirerTrxRes/Issuer/issuerAuthenticationURL/child::text()')[0],
            transaction_id=response.xpath('/AcquirerTrxRes/Transaction/transactionID/child::text()')[0],
            purchase_id=response.xpath('/AcquirerTrxRes/Transaction/purchaseID/child::text()')[0])
    
    def request_transaction_status(self, transaction_id):
        '''Request the status of a transaction'''
        response = self.acquirer.do_request(AcquirerStatusReq(self.merchant, transaction_id))
        
        timestamp = response.xpath('/AcquirerStatusRes/createDateTimeStamp/child::text()')[0]
        acquirer_id = response.xpath('/AcquirerStatusRes/Acquirer/acquirerID/child::text()')[0]
        transaction_id = response.xpath('/AcquirerStatusRes/Transaction/transactionID/child::text()')[0]
        status = response.xpath('/AcquirerStatusRes/Transaction/status/child::text()')[0]       
        if status == 'Success':     
            consumer_name = response.xpath('/AcquirerStatusRes/Transaction/consumerName/child::text()')[0]
            consumer_account_number = response.xpath('/AcquirerStatusRes/Transaction/consumerAccountNumber/child::text()')[0]
            consumer_city = response.xpath('/AcquirerStatusRes/Transaction/consumerCity/child::text()')[0]
        signature = response.xpath('/AcquirerStatusRes/Signature/signatureValue/child::text()')[0]
        fingerprint = response.xpath('/AcquirerStatusRes/Signature/fingerprint/child::text()')[0]
        
        sign_fields = [timestamp, transaction_id, status]
        if status == 'Success':
            sign_fields += [consumer_account_number,]
                
        if not self.acquirer.verify_message(fingerprint, signature, sign_fields):
            raise IDealException('Transaction status is possibly forged')
        
        return AcquirerStatusRes(acquirer_id=acquirer_id,
                                 transaction_id=transaction_id,
                                 status=status,
                                 consumer_name=consumer_name,
                                 consumer_account_number=consumer_account_number,
                                 consumer_city=consumer_city)
         
