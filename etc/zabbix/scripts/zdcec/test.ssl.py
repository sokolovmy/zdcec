
import lib.sslcheck


s = lib.sslcheck.SSLCheck()

ucert, _ = s.getCert('thesis-ecm.com.')

print(ucert.getIssuerStr())
print(ucert.getSubject())
print(ucert.getEndDate())