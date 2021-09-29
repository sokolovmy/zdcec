#!/usr/bin/python3

from lib.sslcheck import SSLCheck
import lib.sslcheck


sslcheck = SSLCheck(timeout=1)

ucert = sslcheck.getCert('mail.haulmont.ru')#mail.haulmont.ru

print(ucert.getAllNames())