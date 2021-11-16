
import logging


config = {
    'dbFileName': '/var/lib/zabbix/zdcec_cache.db',
    'namedConfFile': '/var/lib/zabbix/copy_from_ns0/named/chroot/var/named/zones/forward.zones',
    'namedZonesDir': '/var/lib/zabbix/copy_from_ns0/named/chroot/var/named',
    'logFileName': '/var/log/zabbix/zdcec.log',
    'loggingLevel': logging.DEBUG,
    'loggingToConsole': False,
    'dateTimeFormat': '%Y-%m-%d %H:%M:%S %Z',
    'dbDateTimeFormat': '%Y%m%dT%H%M%SZ',
    'logMaxFiles': 7,
    'logFileSize': 1024*1024
}

version = '0.12'


