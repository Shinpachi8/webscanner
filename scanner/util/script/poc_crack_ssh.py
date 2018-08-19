# coding:utf-8
import paramiko
from config import is_port_open
paramiko.util.logging.getLogger('paramiko.transport').addHandler(paramiko.util.logging.NullHandler())


# @is_port_open
def verify(ip, port=22, name='', timeout=10, types='ip'):
    if types != 'ip':
        return
    
    if name.find('ssh') == -1:
        return
    user_list = ['root', 'admin', 'oracle', 'weblogic']
    PASSWORD_DIC = ['admin', '123456', '12345', 'root', 'toor', '', '{user}123']
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for user in user_list:
        for pass_ in PASSWORD_DIC:
            pass_ = str(pass_.replace('{user}', user))
            try:
                ssh.connect(ip, port, user, pass_, timeout=timeout, allow_agent = False, look_for_keys = False)
                ssh.exec_command('whoami',timeout=timeout)
                if pass_ == '': pass_ = "null"
                info = {
                    "url": "ssh://{}:{}@{}:{}".format(user, pass_, ip, port),
                    "vuln_name": "ssh weak password",
                    "severity": "high",
                    "proof": "username={}&password={}".format(user, pass_)
                }
                return info
            except Exception, e:
                if "Unable to connect" in e or "timed out" in e: return
            finally:
                ssh.close()
