# coding:utf-8
import socket
from config import is_port_open


@is_port_open
def verify(ip, port=6379, name='', timeout=10):
    info = {
        "url": "redis://{}:{}".format(ip, port),
        "vuln_name": "redis weak password",
        "severity": "high",
        "proof": "username={}&password={}"
    }
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send("INFO\r\n")
        result = s.recv(1024)
        if "redis_version" in result:
            info["proof"] = info["proof"].format("None", "None")
            info["vuln_name"] = "redis unauthorized access"
            return info
        elif "Authentication" in result:
            PASSWORD_DIC = ["redis", "123456", "1234qewr", "1q2w3e4r", "admin", "root"]
            for pass_ in PASSWORD_DIC:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ip, int(port)))
                s.send("AUTH %s\r\n" % (pass_))
                result = s.recv(1024)
                if '+OK' in result:
                    info["proof"] = info["proof"].format("None", pass_)
                    return info
    except Exception, e:
        pass
