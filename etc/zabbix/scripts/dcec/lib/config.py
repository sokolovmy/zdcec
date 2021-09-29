
import logging


config = {
    'dbFileName': 'tmp/dcec_cache.db',
    'namedConfFile': 'tmp/named/zones/forward.zones',
    'namedZonesDir': 'tmp/named',
    'logFileName': 'tmp/dcec.log',
    'loggingLevel': logging.DEBUG,
    'loggingToConsole': False,
    'dateTimeFormat': '%Y-%m-%d %H:%M:%S %Z',
    'dbDateTimeFormat': '%Y%m%dT%H%M%SZ',
    'logMaxFiles': 7,
    'logFileSize': 1024*1024
}

version = '0.12'


