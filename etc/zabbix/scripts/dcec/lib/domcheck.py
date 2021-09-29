

from datetime import timezone, datetime
import wizard_whois
import iscpy

import os
import re
import socket


from lib.config import config



def getDomainExpDate(domainName):
    try:
        wdomain = wizard_whois.get_whois(domainName)
        expDate: datetime = min(wdomain['expiration_date'])
        expDate = expDate.replace(tzinfo=timezone.utc)
        return expDate, 0
    except socket.error:
         return None, 1
    except KeyError:
         return None, 2

class DomainsParser:
    '''
        Bind ISC Config file Parser
        Get from config forward domain zones
        
        TODO: add parsing 'include' directive
    '''
    def __init__(self, namedConfFile = config['namedConfFile'], namedZonesDir = config['namedZonesDir']):
        self.namedConfFile = namedConfFile
        self.namedZonesDir = namedZonesDir
        self._domains = None

        self._hosts_ = []
        self._resolvedCnames_ = []
        self._A_ = None
        self._cname_ = None
        

    def getDomains(self):
        if self._domains is None:
            self._domains = {}
            with open(self.namedConfFile) as file:
                fileStr = file.read()
            config = iscpy.dns.MakeNamedDict(fileStr)
            
            for dn in config['orphan_zones']:
                if dn.find('.in-addr.arpa') >= 0:
                    continue
                zoneFile = config['orphan_zones'][dn]['file']
                if not os.path.isabs(zoneFile):
                    relPath = os.path.dirname(self.namedConfFile)
                    zoneFile = os.path.join(relPath, zoneFile)
                self._domains[dn] = zoneFile

        return self._domains

    def getHostsFromDomains(self):
        if self._A_ is None:
            self._A_ = {}
            self._cname_ = {}
            self.getDomains()
            for domainName in self._domains:
                bzp = BindZoneFileParser(self._domains[domainName], domainName)
                self._A_.update(bzp.getA())
                self._cname_.update(bzp.getCname())
            
            self._resolveCnames()
            self._A_.update(self._cname_)
            self._cname_ = None
        return self._A_


    def _resolveCnames(self):
        fordel = []
        for hostName in self._cname_:
            res = self._resolveCname(hostName)
            if res is None:
                fordel.append(hostName)
        for h in fordel:
            self._cname_.pop(h)
        self._resolvedCnames_ = []

    
    def _resolveCname(self, rName):
        if rName in self._resolvedCnames_:
            return self._cname_[rName]
        
        cn = self._cname_[rName]
        if cn in self._A_:
            self._cname_[rName] = self._A_[cn]
            self._resolvedCnames_.append(rName)
            return self._A_[cn]
        
        if cn in self._cname_:
            cn = self._resolveCname(cn)
            if cn:
                self._cname_[rName] = cn
                return cn
        return None
 


class BindZoneFileParser:
    '''
        single Bind zone file parsing for A & CNAME rows
        not all sintax support
        skip * - hostnames
    '''
    def __init__(self, zoneFileName, originDomain, skipLocalhost=True, skipNonLocalDomain=False):
        if originDomain[-1] != '.':
            originDomain += '.'
        self.zoneFileName = zoneFileName
        self.origin = originDomain
        self.skipLocalhost = skipLocalhost
        self.skipNonLocalDomain = skipNonLocalDomain
        self.prevHostname = originDomain #???
        self.A = dict()
        self.Cname = dict()
        #'(?P<hn>\S+)?\s+(?:IN)?\s+(?P<cmd>A|CNAME|SOA|NS|MX)s+(?P<arg>\S+).*'
        self.reCommon = re.compile('(?P<hn>\S+)?\s+(?:\d+\s+)?(?:IN\s+)?(?P<cmd>A|CNAME|SOA|NS|MX|TXT|SRV)\s+(?P<arg>\S+).*' , flags=re.IGNORECASE)
        self.reOrigin = re.compile('\s*\$ORIGIN\s+(\S+).*', flags=re.IGNORECASE)
        self.reIPv4 = re.compile('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

        with open(zoneFileName) as zoneFile:
            zoneStr = zoneFile.read()
            zoneStr = self.__removeComments(zoneStr)
            zoneStrs = zoneStr.split('\n')            
            self.__parseFile(zoneStrs)

    def getA(self):
        return self.A

    def getCname(self):
        return self.Cname
    
    def __parseFile(self, zoneStrs):
        for line in zoneStrs:
            if (len(line) == 0):
                continue
            else:
                self.__parseLine(line)

    def __parseLine(self, line):
        res = self.reOrigin.match(line)
        if res:
            self.origin = res.group(1)
        else:
            res = self.reCommon.match(line)
            if res:
                hostName = res.group('hn')
                if ((not hostName is None) and ('*' in hostName)):
                    return
                hostName = self.__processHostName(hostName)
                cmd = res.group('cmd').upper()
                if (cmd == 'A'):
                    self.__processA(hostName, res.group('arg'))
                elif (cmd == 'CNAME'):
                    self.__processCname(hostName, res.group('arg'))
 
    def __removeComments(self, str):
        #remove all multiline comments
        str = re.sub('/\*[^\*]*\*/', '', str, flags=re.MULTILINE)
        #remove all single line comments
        str = re.sub('^#.*$', '', str, flags=re.MULTILINE)
        #str = re.sub('//.*$', '', str, flags=re.MULTILINE)
        str = re.sub(';.*$', '', str, flags=re.MULTILINE)
        return str
    
    def __processHostName(self, hostName, setPrevHostName=True):
        if (hostName is None or hostName == ''):
            hostName = self.prevHostname
        elif (hostName == '@'):
            hostName = self.origin
            if setPrevHostName:
                self.prevHostname = hostName
        elif (hostName[-1] != '.'):
            if (self.origin[0] != '.'):
                hostName += '.'
            hostName += self.origin
            if setPrevHostName:
                self.prevHostname = hostName
        
        return hostName

    def __processA(self, hostName, str):
        res = self.reIPv4.match(str)
        if res:
            ip = res.group(1)
            if (self.skipLocalhost and ip == '127.0.0.1'):
                return
            if (hostName in self.A):
                self.A[hostName] += ';' + ip
            else:
                self.A[hostName] = ip 
    
    def __processCname(self, hostName, str):
        if ('*' in str):
            return
        cnameHost = self.__processHostName(str, False)
        if (self.skipNonLocalDomain and cnameHost == str):
            return
        self.Cname[hostName] = cnameHost




