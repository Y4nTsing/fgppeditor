# fgppeditor
modify Fine-Grained Password Policy with python


login with password:
```
python .\fgppeditor.py -host 192.168.123.123 -u "testdomain\administrator" -p "123456" -type pass -mode list
```

login with hash:
```
python .\fgppeditor.py -host 192.168.123.123 -u "testdomain\administrator" -p "aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4" -type hash -mode list
```

add fgpp:
```
 python .\fgppeditor.py -host 192.168.123.123 -u "testdomain\administrator" -p "123456" -type pass -mode add -name newtest -applyto "CN=tom,CN=Users,DC=testdomain,DC=test"
 ```
 
 enable msDS-PasswordReversibleEncryptionEnabled:
 ```
 python .\fgppeditor.py -host 192.168.123.123 -u "testdomain\administrator" -p "123456" -type pass -mode modreverse -name test1
 ```
 modify msDS-PasswordSettingsPrecedence:
 ```
 python .\fgppeditor.py -host 192.168.123.123 -u "testdomain\administrator" -p "123456" -type pass -mode modprecedence -name newtest -precedence 2
 ```
 modify msDS-PSOAppliesTo:
 ```
 python .\fgppeditor.py -host 192.168.123.123 -u "testdomain\administrator" -p "123456" -type pass -mode modapplyto -name test2 -applyto "CN=tom,CN=Users,DC=testdomain,DC=test"
 ```
 
 
 ```
usage: fgppeditor.py [-h] [-host HOST] [-u U] [-p P] [-type TYPE] [-mode MODE] [-name NAME] [-applyto APPLYTO]
                     [-precedence PRECEDENCE]

fgppeditor.py -host 192.168.123.123 -u "domain\admin" -p "123456" -type pass -mode xxxx

optional arguments:
  -h, --help            show this help message and exit
  -host HOST            192.168.123.123
  -u U                  domain\domainadmin
  -p P                  pass or hash
  -type TYPE            pass,hash
  -mode MODE            list,add,modreverse,modapplyto,modprecedence
  -name NAME            fgpp name
  -applyto APPLYTO      CN=tom,CN=Users,DC=testdomain,DC=test
  -precedence PRECEDENCE
                        set precedence
 ```
