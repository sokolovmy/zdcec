import logging

from . import __version__

config = {
    'dbFileName': '/tmp/zdcec_cache.db',
    'namedConfFile': '/tmp/ns2/named.zones.conf',
    'namedZonesDir': '/tmp/ns2/zones/',  # mandatory
    'logFileName': '/tmp/zdcec.log',
    'loggingLevel': logging.DEBUG,
    'loggingToConsole': True,
    'dateTimeFormat': '%Y-%m-%d %H:%M:%S %Z',
    'dbDateTimeFormat': '%Y%m%dT%H%M%SZ',
    'logMaxFiles': 7,
    'logFileSize': 1024 * 1024,
    'manual_domains': None, #  {'cisco.com': None, 'yandex.ua': None},
    'manual_hosts': None #  {'www.yandex.ru': None, 'yandex.com': None}
}

version = __version__
