# coding:utf-8
import ftplib
from config import is_port_open


# @is_port_open
def verify(ip, port=21, name="", timeout=10, types='ip'):
    if int(port) != 21 or "ftp" not in name.lower():
        return

    if types != 'ip':
        return
    
    user_list = ['ftp', 'www', 'admin', 'root', 'db', 'wwwroot', 'data', 'web']
    PASSWORD_DIC = ['ftp', 'www', 'admin', 'root', 'db', 'wwwroot', 'data', 'web', '123456', '12345678', '']
    for user in user_list:
        for pass_ in PASSWORD_DIC:
            pass_ = str(pass_.replace('{user}', user))
            try:
                ftp = ftplib.FTP()
                ftp.timeout = timeout
                ftp.connect(ip, port)
                ftp.login(user, pass_)
                if pass_ == '': pass_ = "null"
                info = {
                    "url": "ftp://{}:{}@{}:{}".format(user, pass_, ip, port),
                    "vuln_name": "FTP weak password",
                    "severity": "medium",
                    "proof": "username={}&password={}".format(user, pass_)
                }
                return info
            except Exception, e:
                if "Errno 10061" in str(e) or "timed out" in str(e):
                    print "[poc_crack_ftp] [line 29] [error={}]".format(repr(e))
                    return
