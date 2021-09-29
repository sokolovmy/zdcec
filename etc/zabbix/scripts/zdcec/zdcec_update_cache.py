#!/usr/bin/python3



from lib.config import config
from lib.log import logger

import lib.db
import lib.domcheck
import lib.sslcheck
import getopt

from pprint import pprint


logger.info("Cache update starts.")
try:
    db = lib.db.CacheDB(config['dbFileName'])
    logger.info("Collecting information about domains.")
    counter = 0
    domainParser = lib.domcheck.DomainsParser()
    for domainName in domainParser.getDomains():
        expDate, error = lib.domcheck.getDomainExpDate(domainName)
        if expDate:
            db.addDomain(domainName, expDate)
            logger.debug(f"Domain '{domainName}' expired at {expDate.strftime(config['dateTimeFormat'])}")
            counter += 1
        if error == 1: # Connection Error
            logger.error(f"Cannot connect to whois server to check domain info about '{domainName}'")
        elif error == 2: # Registration error maybe.
            logger.warning(f"Cannot get information about the domain '{domainName}'. Is it not registered, may be?")
    logger.debug(f'Information updated on {counter} domains')
    logger.info('Collecting information about hosts')
    hosts = domainParser.getHostsFromDomains()
    sslCheck = lib.sslcheck.SSLCheck(timeout=1)
    counter = 0
    for host in hosts:
        logger.info(f"Trying to get a cert for '{host}'.")
        cert = sslCheck.getCert(host)
        if cert:
            db.addHostWithCert(host, cert.toPEM())
            logger.debug(f"The certificate for the host '{host}' is saved in the cache.")
            counter += 1
        else:
            logger.warning(f"Cannot save the certificate for the host '{host}'. Host or web service is down?")
    logger.debug(f'Information updated on {counter} hosts')


except BaseException as e:
    logger.error(e, exc_info=True)

logger.info("Cache update done.")
