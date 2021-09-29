
import logging


config = {
    'dbFileName': 'tmp/zdcec_cache.db',
    'namedConfFile': 'tmp/named/zones/forward.zones',
    'namedZonesDir': 'c:/Github/zdcec/tmp/named',
    'logFileName': 'tmp/zdcec.log',
    'loggingLevel': logging.DEBUG,
    'loggingToConsole': True,
    'dateTimeFormat': '%Y-%m-%d %H:%M:%S %Z',
    'dbDateTimeFormat': '%Y%m%dT%H%M%SZ',
    'logMaxFiles': 7,
    'logFileSize': 1024*1024
}

version = '0.12'


