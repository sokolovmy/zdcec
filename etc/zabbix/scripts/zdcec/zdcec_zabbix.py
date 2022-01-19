#!/usr/bin/python3

import json
import sys
from datetime import datetime, timezone

import lib.db
import lib.sslcheck
from lib.config import version
from lib.db import fromDbDateTime
from lib.sslcheck import UCert, getDateTimeStr


def usage():
    print(f'''
Zabbix Domain/Cert Expire Check.

version {version}

Usage: {sys.argv[0]} command [ argument ]

    listdomains - list cached domains
    domain <name of domain> - show more info about domain
    listcerts - list cached certs
    cert <_id_ of cert> - show more info about cert
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
    cur_date = datetime.now(tz=timezone.utc)
    # domain_name, expire_date, last_update
    for domain_data in db.getDomainsData():
        exp_date = lib.db.fromDbDateTime(domain_data[1])
        d_obj = {
            '{#DOMAIN}': domain_data[0],
            '{#EXPDATE}': getDateTimeStr(exp_date),
            '{#CACHEDATE}': getDateTimeStr(fromDbDateTime(domain_data[2]))}
        delta = exp_date - cur_date
        d_obj['{#EXPDAYS}'] = delta.days
        dl.append(d_obj)
    print(json.dumps(dl, indent=2))


def domain(domainName):
    try:
        dd = db.getDomainData(domainName)
        exp_date = lib.db.fromDbDateTime(dd[0])
        cur_date = datetime.now(tz=timezone.utc)
        # expire_date, last_update
        d_obj = {
            'ExpDate': getDateTimeStr(exp_date),
            'ExpDays': (exp_date - cur_date).days,
            'CacheDate': getDateTimeStr(lib.db.fromDbDateTime(dd[1]))
        }
    except:
        d_obj = {
            'ExpDate': '',
            'ExpDays': 2 ** 31,
            'CacheDate': ''
        }
    print(json.dumps(d_obj, indent=2))


def listCerts():
    cl = []
    cur_date = datetime.now(tz=timezone.utc)
    # _id_, cert, last_update
    for certRow in db.getCerts():
        u_cert = UCert(certPEM=certRow[1])
        c_obj = {
            '{#ID}': certRow[0],
            '{#CACHEDATE}': getDateTimeStr(fromDbDateTime(certRow[2]))
        }
        exp_date = u_cert.getEndDate()
        c_obj['{#EXPDATE}'] = getDateTimeStr(exp_date)
        delta = exp_date - cur_date
        c_obj['{#EXPDAYS}'] = delta.days
        c_obj['{#COMNAME}'] = u_cert.getSubjectCommonName()
        c_obj['{#SUBJECT}'] = u_cert.getSubjectStr()
        c_obj['{#ISSUER}'] = u_cert.getIssuerStr()
        c_obj['{#SERIAL}'] = str(u_cert.getSerial())
        c_obj['{#VERSION}'] = u_cert.getVersion()
        c_obj['{#SUBJECTALTNAME}'] = u_cert.getSubjectAltNameStr()
        c_obj['{#HOSTS}'] = ', '.join(db.getHostsByCertId(certRow[0]))
        cl.append(c_obj)
    print(json.dumps(cl, indent=2))


def cert(certId):
    try:
        cd = db.getCertById(certId)
        # cert, last_update
        u_cert = UCert(certPEM=cd[0])
        exp_date = u_cert.getEndDate()
        cur_date = datetime.now(tz=timezone.utc)
        c_obj = {
            'CacheDate': getDateTimeStr(lib.db.fromDbDateTime(cd[1])),
            'ExpDate': getDateTimeStr(exp_date),
            'ExpDays': (exp_date - cur_date).days,
            'Hosts': ', '.join(db.getHostsByCertId(certId)),
            'ComName': u_cert.getSubjectCommonName(),
            "Subject": u_cert.getSubjectStr(),
            'Issuer': u_cert.getIssuerStr(),
            'Serial': str(u_cert.getSerial()),
            'Version': u_cert.getVersion(),
            'SubjectAllName': u_cert.getSubjectAltNameStr()
        }
    except:
        v = ['CacheDate', 'ExpDate', 'Hosts', 'ComName', 'Subject', 'Issuer', 'Serial', 'Version', 'SubjectAllName']
        c_obj = {}
        for i in v:
            c_obj[i] = ''
        c_obj['ExpDays'] = 2 ** 31

    print(json.dumps(c_obj, indent=2))


if __name__ == '__main__':
    try:
        db = lib.db.CacheDB()
        opts()
    except:
        print("ZBX_NOTSUPPORTED: Unsupported item key.")
        sys.exit(-1)
