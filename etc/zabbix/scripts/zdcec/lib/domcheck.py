import os
import re
import socket
from datetime import timezone, datetime

# pip install https://github.com/egberts/iscpy/archive/refs/heads/master.zip
import iscpy
import wizard_whois

from .config import config


def getDomainExpDate(domainName):
    try:
        w_domain = wizard_whois.get_whois(domainName)
        exp_date: datetime = min(w_domain['expiration_date'])
        exp_date = exp_date.replace(tzinfo=timezone.utc)
        return exp_date, 0
    except socket.error:
        return None, 1
    except KeyError:
        return None, 2


class DomainsParser:
    """
        Bind ISC Config file Parser
        Get from config forward domain zones

        TODO: add parsing 'include' directive
    """

    def __init__(self, namedConfFile=config['namedConfFile'], namedZonesDir=config.get('namedZonesDir')):
        self.namedConfFile = namedConfFile
        self.namedZonesDir = namedZonesDir
        self._domains = None

        self._hosts_ = []
        self._resolvedCNAMEs_ = []
        self._A_ = None
        self._cname_ = None

    def getDomains(self):
        if self._domains is None:
            self._domains = {}
            with open(self.namedConfFile) as file:
                file_str = file.read()
            named_config = iscpy.dns.MakeNamedDict(file_str)

            for dn in named_config['orphan_zones']:
                if dn.find('.in-addr.arpa') >= 0:
                    continue
                zone_file = named_config['orphan_zones'][dn]['file']
                if self.namedZonesDir:
                    zone_file = os.path.basename(zone_file)
                    zone_file = os.path.join(self.namedZonesDir, zone_file)
                elif not os.path.isabs(zone_file):
                    zone_file = os.path.join(os.path.dirname(self.namedConfFile), zone_file)
                self._domains[dn] = zone_file

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

            self._resolveCNAMEs()
            self._A_.update(self._cname_)
            self._cname_ = None
        return self._A_

    def _resolveCNAMEs(self):
        for_del = []
        for hostName in self._cname_:
            res = self._resolveCNAME(hostName)
            if res is None:
                for_del.append(hostName)
        for h in for_del:
            self._cname_.pop(h)
        self._resolvedCNAMEs_ = []

    def _resolveCNAME(self, rName):
        if rName in self._resolvedCNAMEs_:
            return self._cname_[rName]

        cn = self._cname_[rName]
        if cn in self._A_:
            self._cname_[rName] = self._A_[cn]
            self._resolvedCNAMEs_.append(rName)
            return self._A_[cn]

        if cn in self._cname_:
            cn = self._resolveCNAME(cn)
            if cn:
                self._cname_[rName] = cn
                return cn
        return None


class BindZoneFileParser:
    """
        single Bind zone file parsing for A & CNAME rows
        not all syntax support
        skip * - hostnames
    """

    def __init__(self, zoneFileName, originDomain, skipLocalhost=True, skipNonLocalDomain=False):
        if originDomain[-1] != '.':
            originDomain += '.'
        self.zoneFileName = zoneFileName
        self.origin = originDomain
        self.skipLocalhost = skipLocalhost
        self.skipNonLocalDomain = skipNonLocalDomain
        self.prevHostname = originDomain  # ???
        self.A = dict()
        self.Cname = dict()
        # '(?P<hn>\S+)?\s+(?:IN)?\s+(?P<cmd>A|CNAME|SOA|NS|MX)s+(?P<arg>\S+).*'
        self.reCommon = re.compile(
            '(?P<hn>\S+)?\s+(?:\d+\s+)?(?:IN\s+)?(?P<cmd>A|CNAME|SOA|NS|MX|TXT|SRV)\s+(?P<arg>\S+).*',
            flags=re.IGNORECASE)
        self.reOrigin = re.compile('\s*\$ORIGIN\s+(\S+).*', flags=re.IGNORECASE)
        self.reIPv4 = re.compile('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

        with open(zoneFileName) as zoneFile:
            zone_str = zoneFile.read()
            zone_str = self.__removeComments(zone_str)
            zone_strs = zone_str.split('\n')
            self.__parseFile(zone_strs)

    def getA(self):
        return self.A

    def getCname(self):
        return self.Cname

    def __parseFile(self, zone_strs):
        for line in zone_strs:
            if len(line) == 0:
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
                host_name = res.group('hn')
                if (host_name is not None) and ('*' in host_name):
                    return
                host_name = self.__processHostName(host_name)
                cmd = res.group('cmd').upper()
                if cmd == 'A':
                    self.__processA(host_name, res.group('arg'))
                elif cmd == 'CNAME':
                    self.__processCname(host_name, res.group('arg'))

    @staticmethod
    def __removeComments(s):
        # remove all multiline comments
        s = re.sub(r'/\*[^*]*\*/', '', s, flags=re.MULTILINE)
        # remove all single line comments
        s = re.sub('^#.*$', '', s, flags=re.MULTILINE)
        # s = re.sub('//.*$', '', s, flags=re.MULTILINE)
        s = re.sub(';.*$', '', s, flags=re.MULTILINE)
        return s

    def __processHostName(self, host_name, setPrevHostName=True):
        if host_name is None or host_name == '':
            host_name = self.prevHostname
        elif host_name == '@':
            host_name = self.origin
            if setPrevHostName:
                self.prevHostname = host_name
        elif host_name[-1] != '.':
            if self.origin[0] != '.':
                host_name += '.'
            host_name += self.origin
            if setPrevHostName:
                self.prevHostname = host_name

        return host_name

    def __processA(self, hostName, s):
        res = self.reIPv4.match(s)
        if res:
            ip = res.group(1)
            if self.skipLocalhost and ip == '127.0.0.1':
                return
            if hostName in self.A:
                self.A[hostName] += ';' + ip
            else:
                self.A[hostName] = ip

    def __processCname(self, hostName, s):
        if '*' in s:
            return
        cname_host = self.__processHostName(s, False)
        if self.skipNonLocalDomain and cname_host == s:
            return
        self.Cname[hostName] = cname_host
