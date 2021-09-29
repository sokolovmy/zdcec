
#pip install pyasn1
#pip install pyasn1_modules
# Import pyasn and the proper decode function
import pyasn1
from pyasn1.codec.der.decoder import decode as asn1_decoder
# Import SubjectAltName from rfc2459 module
from pyasn1_modules.rfc2459 import SubjectAltName
# Import native Python type encoder
from pyasn1.codec.native.encoder import encode as nat_encoder


#pip install pyopenssl
from OpenSSL.SSL import Connection, Context, SSLv3_METHOD, TLSv1_2_METHOD
import OpenSSL
import OpenSSL.crypto
from OpenSSL.crypto import FILETYPE_PEM, X509
from datetime import datetime, timezone, timedelta, tzinfo

import socket
import string

from lib.config import config


def getDateTimeStr(dt: datetime):
    return dt.strftime(config['dateTimeFormat'])

class UCert:
    def __init__(self, X509Cert: X509 = None, certPEM: string = None):
        if X509Cert:
            self.X509Cert = X509Cert
        elif certPEM:
            self.X509Cert = OpenSSL.crypto.load_certificate(FILETYPE_PEM, certPEM)
        else:
            self.X509Cert = None

        self.subject = None
        self.issuer = None
        self.extList = None
    
    def toPEM(self):
        return OpenSSL.crypto.dump_certificate(FILETYPE_PEM, self.X509Cert)

    def getEndDate(self):
        return datetime.strptime(
            str(self.X509Cert.get_notAfter().decode('utf-8')),
            "%Y%m%d%H%M%SZ"
        ).replace(tzinfo=timezone.utc)
    
    def getStartDate(self):
        return datetime.strptime(
            str(self.X509Cert.get_notBefore().decode('utf-8')),
            "%Y%m%d%H%M%SZ"
        ).replace(tzinfo=timezone.utc)

    def isExpired(self):
        return self.X509Cert.has_expired()
    
    def getVersion(self):
        return self.X509Cert.get_version()

    def getSerial(self):
        return self.X509Cert.get_serial_number()

    def getIssuer(self):
        if self.issuer is None:
            isld = {}
            for item in self.X509Cert.get_issuer().get_components():
                isld[item[0].decode('utf-8').upper()] = item[1].decode('utf-8')
            self.issuer = isld
        return self.issuer

    def getIssuerStr(self):
        return '/'.join([f"{i}={self.getIssuer()[i]}" for i in self.getIssuer()])

    def getSubject(self):
        if self.subject is None:
            sld = {}
            for item in self.X509Cert.get_subject().get_components():
                sld[item[0].decode('utf-8').upper()] = item[1].decode('utf-8')
            self.subject = sld
        return self.subject
    def getSubjectCommonName(self):
        return self.getSubject().get('CN')

    def getSubjectStr(self):
        return '/'.join([f"{i}={self.getSubject()[i]}" for i in self.getSubject()])

    def getExtList(self):
        if self.extList is None:
            el = {}
            for i in range(0, self.X509Cert.get_extension_count() - 1):
                ext = self.X509Cert.get_extension(i)
                #decoded_alt_names, _ = asn1_decoder(ext.get_data(), asn1Spec=SubjectAltName())
                el[ext.get_short_name().decode('utf-8')] = ext.get_data()
                
            self.extList = el

        return self.extList
    def getSubjectAltName(self):
        san = self.getExtList().get('subjectAltName')
        if san:
            san, _ = asn1_decoder(san, asn1Spec=SubjectAltName())
            san = nat_encoder(san)           
            return [ x['dNSName'].decode('utf-8') for x in san]
        return None

    def getSubjectAltNameStr(self):
        s = self.getSubjectAltName()
        if s:
            return ', '.join(self.getSubjectAltName())
        else:
            return None

    def getAllNames(self):
        nl = self.getSubjectAltName()
        if nl:
            cn = self.getSubject().get('CN')
            if cn not in nl:
                nl.append(cn)
        return nl
    
    def getAllNamesStr(self):
        return ', '.join(self.getAllNames())

class SSLCheck:
    def __init__(self, timeout=1)#, socketTimeout=None):
        #self.timeout = socketTimeout if socketTimeout else timeout
        try:
            self.ssl_connection_setting = Context(SSLv3_METHOD)
        except ValueError:
            self.ssl_connection_setting = Context(TLSv1_2_METHOD)
        self.ssl_connection_setting.set_timeout(timeout)

    def getCert(self, hostName):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                #s.settimeout(self.timeout)
                #TODO: this is not working. need to try another way
                s.connect((hostName, 443))
                c = Connection(self.ssl_connection_setting, s)
                c.set_tlsext_host_name(str.encode(hostName))
                c.set_connect_state()
                c.do_handshake()
                cert = c.get_peer_certificate()
                c.shutdown()
                s.close()
                return UCert(cert)
        except BaseException as e:
            print(e)
            return None
    