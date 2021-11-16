'''
TODO:
    разработать процедуру удаления устаревших данных
'''

import sqlite3
from sqlite3.dbapi2 import Cursor, connect
import itertools
from datetime import datetime, timezone

from lib.config import config


_create_certs_db_sql_ = '''
CREATE TABLE IF NOT EXISTS certs (
    id INTEGER PRIMARY KEY,
    cert text UNIQUE,
    last_update VARCHAR(30) NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
    hostname varchar(255) UNIQUE,
    cert_id INTEGER NOT NULL,
    last_update VARCHAR(30) NOT NULL,
    FOREIGN KEY(cert_id) REFERENCES certs(id)
);
CREATE TABLE IF NOT EXISTS domains (
    domain_name VARCHAR(255) UNIQUE,
    expire_date VARCHAR(30) NOT NULL,
    last_update VARCHAR(30) NOT NULL,
    checked TINYINT NOT NULL DEFAULT 1
)
'''


def fromDbDateTime(str):
    return datetime.strptime(str, config['dbDateTimeFormat']).replace(tzinfo=timezone.utc)


class CacheDB:
    def __init__(self, dbFileName=config['dbFileName']):
        self.con = sqlite3.connect(dbFileName)
        self._initDB()

    def __del__(self):
        self.con.close()

    def _initDB(self):
        cur = self.con.cursor()
        cur.executescript(_create_certs_db_sql_)
        self.con.commit()

    def _execSQL(self, SQL, params=None, commit=True, fetchResult=True):
        cur = self.con.cursor()
        if params:
            cur.execute(SQL, params)
        else:
            cur.execute(SQL)
        res = None
        if fetchResult:
            res = cur.fetchall()
        cur.close()
        self.commit()
        return res

    def removeUnusedCerts(self):
        self._execSQL(
            "DELETE FROM certs WHERE id NOT IN (SELECT cert_id FROM hosts GROUP BY cert_id);",
            fetchResult=False
        )

    def removeNotFoundDomains(self, domains, commit=True):
        self._execSQL("UPDATE domains SET checked = 0", fetchResult=False, commit=False)
        for domain in domains:
            self._execSQL("UPDATE domains SET checked = 1 WHERE domain_name = ?", (domain,),
                          fetchResult=False, commit=False)
        self._execSQL("DELETE FROM domains WHERE checked = 0", fetchResult=False, commit=False)
        self.commit(commit=commit)

    def _getCurDateTime(self):
        curDate = datetime.now(tz=timezone.utc)
        curDate = curDate.strftime(config['dbDateTimeFormat'])
        return curDate

    def commit(self, commit=True):
        if commit:
            self.con.commit()

    def addCert(self, certStr, commit=True):
        curDate = self._getCurDateTime()
        self._execSQL(
            "INSERT INTO certs (cert, last_update) VALUES (?, ?) ON CONFLICT (cert) DO UPDATE SET last_update = ?",
            (certStr, curDate, curDate,),
            fetchResult=False,
            commit=commit
        )
        result = self._execSQL("SELECT id FROM certs WHERE CERT = ?", (certStr,), commit=commit)
        return result[0][0]

    def addHost(self, cert_id, hostName, commit=True):
        curDate = self._getCurDateTime()
        self._execSQL(
            "INSERT INTO hosts (hostname, cert_id, last_update) VALUES (?, ?, ?)"
            " ON CONFLICT (hostname) DO UPDATE SET cert_id = ?, last_update = ?",
            (hostName, cert_id, curDate, cert_id, curDate,),
            commit=commit
        )

    def addHostWithCert(self, hostName, certStr):
        cert_id = self.addCert(certStr, commit=False)
        self.addHost(cert_id, hostName, commit=False)
        self.commit()

    def getCertById(self, id):
        res = self._execSQL("SELECT cert, last_update FROM certs WHERE id = ?", (id,))
        return res[0]

    def getCerts(self):
        return self._execSQL("SELECT id, cert, last_update FROM certs")

    def getHostsByCertId(self, cert_id):
        rows = self._execSQL("SELECT hostname FROM hosts WHERE cert_id = ? ORDER BY hostname ASC", (cert_id,))
        return tuple(itertools.chain.from_iterable(rows))

    def addDomain(self, domainName, expireDate: datetime, commit=True):
        if expireDate:
            expireDate = expireDate.strftime(config['dbDateTimeFormat'])
            curDate = self._getCurDateTime()
            self._execSQL(
                "INSERT INTO domains (domain_name, expire_date, last_update, checked)"
                " VALUES (?, ?, ?, 1) ON CONFLICT (domain_name)"
                " DO UPDATE SET expire_date = ?, last_update = ?, checked = 1",
                (domainName, expireDate, curDate, expireDate, curDate,),
                fetchResult=False,
                commit=commit
            )

    def getDomainData(self, domainName):
        return self._execSQL('SELECT expire_date, last_update FROM domains WHERE domain_name = ?', (domainName,))[0]

    def getDomainsData(self):
        return self._execSQL('SELECT domain_name, expire_date, last_update FROM domains ORDER BY last_update ASC')
