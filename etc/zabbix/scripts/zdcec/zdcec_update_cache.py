#!/usr/bin/python3

import lib.db
import lib.domcheck
# import lib.sslcheck
from lib.config import config
from lib.log import logger
from ssl import get_server_certificate

logger.info("Cache update starts.")
try:
    db = lib.db.CacheDB(config['dbFileName'])
    logger.info("Collecting information about domains.")
    start_base_cast = db.getBaseCast()  # for logging changes
    counter = 0
    domainParser = lib.domcheck.DomainsParser()
    domains = domainParser.getDomains()
    if config.get('manual_domains'):
        domains.update(config['manual_domains'])
    for domainName in domains:
        expDate, error = lib.domcheck.getDomainExpDate(domainName)
        if expDate:
            db.addDomain(domainName, expDate)
            logger.debug(f"Domain '{domainName}' expired at {expDate.strftime(config['dateTimeFormat'])}")
            counter += 1
        if error == 1:  # Connection Error
            logger.error(f"Cannot connect to whois server to check domain info about '{domainName}'")
        elif error == 2:  # Registration error maybe.
            logger.warning(f"Cannot get information about the domain '{domainName}'. Is it not registered, may be?")
    logger.debug(f'Information updated on {counter} domains')
    logger.info('Collecting information about hosts')
    hosts = domainParser.getHostsFromDomains()
    if config.get('manual_hosts'):
        hosts.update(config['manual_hosts'])

    logger.info('Deleting old hosts information from database')
    db.flushHostsTable()
    # sslCheck = lib.sslcheck.SSLCheck(timeout=5)
    counter = 0
    for host in hosts:
        logger.info(f"Trying to get a cert for '{host}'.")
        if host[-1] == '.':
            host = host[:-1]
        # cert, exception = sslCheck.getCert(host)        
        try:
            certPEM = get_server_certificate((host, 443))#, timeout=5) # timeout from 3.10 python
            db.addHostWithCert(host, certPEM)
            logger.debug(f"The certificate for the host '{host}' is saved in the cache.")
            counter += 1
        except Exception as e:
            logger.warning(f"Cannot save the certificate for the host '{host}'. Host or web service is down?")
            logger.error(e)

    logger.debug(f'Information updated on {counter} hosts')

    logger.info("Removing outdated information from cache")
    logger.info("Deleting unused certificates")
    db.removeUnusedCerts()
    logger.info("Deleting domains which are not in the Bind configuration")
    db.removeNotFoundDomains(domainParser.getDomains())
    logger.info('Clearing cache completed')
    db.commit()
    logger.info('Updates committed to database')

    # Logging changes in database (hosts, domains, certs) to the database table logs
    db.saveCastDiffToLog(start_base_cast)
    print('test')
except BaseException as e:
    logger.error(e, exc_info=True)

logger.info("Cache update done.")
