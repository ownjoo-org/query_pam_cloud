# query_pam_cloud
query CyberArk Privilege Cloud for Accounts

# SECURITY NOTE:
I wrote the .py file.  You have my word that they don't do anything nefarious.  Even so, I recommend that you perform
your own static analysis and supply chain testing before use.  Many libraries are imported that are not in my own control.

# usage
```
$ python query_pam_cloud.py 
usage: query_pam_cloud.py [-h] --subdomain SUBDOMAIN --username USERNAME --password PASSWORD --auth_method {Cyberark,LDAP,RADIUS} [--search SEARCH] [--proxies PROXIES]
```


# example: look up accounts
`python query_pam_cloud.py --subdomain MySubdomain --username MyUserName --password MyPassword --auth_method Cyberark`<br>

# references: 
https://docs.cyberark.com/privilege-cloud-standard/Latest/en/Content/WebServices/Implementing%20Privileged%20Account%20Security%20Web%20Services%20.htm?tocpath=Developers%7CREST-APIs%7CREST%20APIs%7C_____0<br>

# related curl commands:
## Logon:
curl -LkX POST -H 'Content-Type: application/json' -H 'Accept: application/json' https://mysubdomain.privilegecloud.cyberark.com/PasswordVault/API/auth/Cyberark/Logon/ -d '{"username": "MyUserName", "password": "MyPassword"}'
Response should contain the token for subsequent requests: {"<session token>"}

## GET ACCOUNTS:
curl -Lk -H 'Content-Type: application/json' -H 'Accept: application/json' https://mysubdomain.privilegecloud.cyberark.com/PasswordVault/API/Accounts?offset=0&limit=1&search=bob
