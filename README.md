# zdcec - Zabbix Domain/Cert Expire Check
Reminder for renewing domains and certificates.

zdcec_update_cache.py
---
Run periodically, scans bind files for domains and hosts. Refreshes the cache.

zdcec_zabbix.py
---
Script for zabbix_agent

zdcec_tpl.xml
---
Template for Zabbix server. It needs to be applied to the bind server added to Zabbix server.
Domains / certificates will be automatically created and deleted.