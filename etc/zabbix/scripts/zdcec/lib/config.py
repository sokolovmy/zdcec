import logging

from . import __version__

config = {
    'dbFileName': 'c:/Github/zdcec/tmp/zdcec_cache.db',
    'namedConfFile': 'c:/Github/zdcec/tmp/ns2/named.zones.conf',
    'namedZonesDir': 'c:/Github/zdcec/tmp/ns2/zones/',  # mandatory
    'logFileName': 'c:/Github/zdcec/tmp/zdcec.log',
    'loggingLevel': logging.DEBUG,
    'loggingToConsole': True,
    'dateTimeFormat': '%Y-%m-%d %H:%M:%S %Z',
    'dbDateTimeFormat': '%Y%m%dT%H%M%SZ',
    'logMaxFiles': 7,
    'logFileSize': 1024 * 1024
}

version = __version__
