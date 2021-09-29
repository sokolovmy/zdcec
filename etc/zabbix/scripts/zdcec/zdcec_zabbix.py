#!/usr/bin/python3

from datetime import datetime, timezone
from lib.config import config
from lib.config import version
from lib.log import logger

import lib.db
from lib.db import fromDbDateTime
import lib.sslcheck
from lib.sslcheck import UCert, getDateTimeStr
import sys
import json

def usage():
    print(f'''
Zabbix Domain/Cert Expire Check.

version {version}

Usage: {sys.argv[0]} command [ argument ]

    listdomains - list cached domains
    domain <name of domain> - show more info about domain
    listcerts - list cached certs
    cert <id of cert> - show more info aboud cert
    ''')
def opts():
    if len(sys.argv) <= 1:
        usage()
    elif sys.argv[1] == 'listdomains':
        listDomains()
    elif sys.argv[1] == 'listcerts':
        listCerts()
    elif len(sys.argv) == 3:
        if sys.argv[1] == 'domain':
            domain(sys.argv[2])
        elif sys.argv[1] == 'cert' and sys.argv[2].isnumeric():
            cert(sys.argv[2])
        else:
            usage()
    else:
        usage()



def listDomains():
    dl = [] 
    curDate = datetime.now(tz=timezone.utc)   
    #domain_name, expire_date, last_update
    for domain in db.getDomainsData():
        expDate = lib.db.fromDbDateTime(domain[1])
        dObj = {}
        dObj['{#DOMAIN}'] = domain[0]
        dObj['{#EXPDATE}'] = getDateTimeStr(expDate)
        dObj['{#CACHEDATE}'] = getDateTimeStr(fromDbDateTime(domain[2]))
        delta =  expDate - curDate
        dObj['{#EXPDAYS}'] = delta.days
        dl.append(dObj)
    print(json.dumps(dl, indent=2))

def domain(domainName):
    dd = db.getDomainData(domainName)
    expDate = lib.db.fromDbDateTime(dd[0])
    curDate = datetime.now(tz=timezone.utc)
    #expire_date, last_update
    dObj = {
        'ExpDate': getDateTimeStr(expDate),
        'ExpDays': (expDate - curDate).days,
        'CacheDate': getDateTimeStr(lib.db.fromDbDateTime(dd[1]))
    }
    print(json.dumps(dObj, indent=2))


def listCerts():
    cl = []
    curDate = datetime.now(tz=timezone.utc)
    # id, cert, last_update
    for certRow in db.getCerts():
        ucert = UCert(certPEM=certRow[1])
        cObj = {}
        cObj['{#ID}'] = certRow[0]
        cObj['{#CACHEDATE}'] = getDateTimeStr(fromDbDateTime(certRow[2]))
        expDate = ucert.getEndDate()
        cObj['{#EXPDATE}'] = getDateTimeStr(expDate)
        delta = expDate - curDate
        cObj['{#EXPDAYS}'] = delta.days
        cObj['{#COMNAME}'] = ucert.getSubjectCommonName()
        cObj['{#SUBJECT}'] = ucert.getSubjectStr() 
        cObj['{#ISSUER}'] = ucert.getIssuerStr()
        cObj['{#SERIAL}'] = str(ucert.getSerial())
        cObj['{#VERSION}'] = ucert.getVersion()
        cObj['{#SUBJECTALTNAME}'] = ucert.getSubjectAltNameStr()
        cObj['{#HOSTS}'] = ', '.join(db.getHostsByCertId(certRow[0]))
        cl.append(cObj)
    print(json.dumps(cl, indent=2))

def cert(certId):
    cd = db.getCertById(certId)
    #cert, last_update
    ucert = UCert(certPEM=cd[0])
    expDate = ucert.getEndDate()
    curDate = datetime.now(tz=timezone.utc)
    cObj = {
        'CacheDate': getDateTimeStr(lib.db.fromDbDateTime(cd[1])),
        'ExpDate': getDateTimeStr(expDate),
        'ExpDays': (expDate - curDate).days,
        'Hosts': ', '.join(db.getHostsByCertId(certId)),
        'ComName': ucert.getSubjectCommonName(),
        "Subject": ucert.getSubjectStr(),
        'Issuer': ucert.getIssuerStr(),
        'Serial': str(ucert.getSerial()),
        'Version': ucert.getVersion(),
        'SubjectAllName': ucert.getSubjectAltNameStr()
    }
    print(json.dumps(cObj, indent=2))

if __name__ == '__main__':
    db = lib.db.CacheDB()
    opts()