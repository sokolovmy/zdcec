
import sqlite3
import itertools
from datetime import datetime, timezone

from .config import config


_create_certs_db_sql_ = '''
CREATE TABLE IF NOT EXISTS certs (
    _id_ INTEGER PRIMARY KEY,
    cert text UNIQUE,
    last_update VARCHAR(30) NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
    hostname varchar(255) UNIQUE,
    cert_id INTEGER NOT NULL,
    last_update VARCHAR(30) NOT NULL,
    FOREIGN KEY(cert_id) REFERENCES certs(_id_)
);
CREATE TABLE IF NOT EXISTS domains (
    domain_name VARCHAR(255) UNIQUE,
    expire_date VARCHAR(30) NOT NULL,
    last_update VARCHAR(30) NOT NULL,
    checked TINYINT NOT NULL DEFAULT 1
)
'''


def fromDbDateTime(s):
    return datetime.strptime(s, config['dbDateTimeFormat']).replace(tzinfo=timezone.utc)


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
        self.commit(commit)
        return res

    def removeUnusedCerts(self):
        self._execSQL(
            "DELETE FROM certs WHERE _id_ NOT IN (SELECT cert_id FROM hosts GROUP BY cert_id);",
            fetchResult=False
        )

    def removeNotFoundDomains(self, domains, commit=True):
        self._execSQL("UPDATE domains SET checked = 0", fetchResult=False, commit=False)
        for domain in domains:
            self._execSQL("UPDATE domains SET checked = 1 WHERE domain_name = ?", (domain,),
                          fetchResult=False, commit=False)
        self._execSQL("DELETE FROM domains WHERE checked = 0", fetchResult=False, commit=False)
        self.commit(commit=commit)

    @staticmethod
    def _getCurDateTime():
        cur_date = datetime.now(tz=timezone.utc)
        cur_date = cur_date.strftime(config['dbDateTimeFormat'])
        return cur_date

    def commit(self, commit=True):
        if commit:
            self.con.commit()

    def addCert(self, certStr, commit=True):
        cur_date = self._getCurDateTime()
        self._execSQL(
            "INSERT INTO certs (cert, last_update) VALUES (?, ?) ON CONFLICT (cert) DO UPDATE SET last_update = ?",
            (certStr, cur_date, cur_date,),
            fetchResult=False,
            commit=commit
        )
        result = self._execSQL("SELECT _id_ FROM certs WHERE CERT = ?", (certStr,), commit=commit)
        return result[0][0]

    def addHost(self, cert_id, hostName, commit=True):
        cur_date = self._getCurDateTime()
        self._execSQL(
            "INSERT INTO hosts (hostname, cert_id, last_update) VALUES (?, ?, ?)"
            " ON CONFLICT (hostname) DO UPDATE SET cert_id = ?, last_update = ?",
            (hostName, cert_id, cur_date, cert_id, cur_date,),
            commit=commit
        )

    def addHostWithCert(self, hostName, certStr):
        cert_id = self.addCert(certStr, commit=False)
        self.addHost(cert_id, hostName, commit=False)
        self.commit()

    def getCertById(self, _id_):
        res = self._execSQL("SELECT cert, last_update FROM certs WHERE _id_ = ?", (_id_,))
        return res[0]

    def getCerts(self):
        return self._execSQL("SELECT _id_, cert, last_update FROM certs")

    def getHostsByCertId(self, cert_id):
        rows = self._execSQL("SELECT hostname FROM hosts WHERE cert_id = ? ORDER BY hostname ASC", (cert_id,))
        return tuple(itertools.chain.from_iterable(rows))

    def addDomain(self, domain_name, expire_date: datetime, commit=True):
        if expire_date:
            expire_date = expire_date.strftime(config['dbDateTimeFormat'])
            cur_date = self._getCurDateTime()
            self._execSQL(
                "INSERT INTO domains (domain_name, expire_date, last_update, checked)"
                " VALUES (?, ?, ?, 1) ON CONFLICT (domain_name)"
                " DO UPDATE SET expire_date = ?, last_update = ?, checked = 1",
                (domain_name, expire_date, cur_date, expire_date, cur_date,),
                fetchResult=False,
                commit=commit
            )

    def getDomainData(self, domainName):
        return self._execSQL('SELECT expire_date, last_update FROM domains WHERE domain_name = ?', (domainName,))[0]

    def getDomainsData(self):
        return self._execSQL('SELECT domain_name, expire_date, last_update FROM domains ORDER BY last_update ASC')
