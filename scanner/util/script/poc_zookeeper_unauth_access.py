# coding=utf-8
import socket
from config import is_port_open


@is_port_open
def verify(ip, port=2181, name=None, timeout=10):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        flag = "envi"
        # envi
        # dump
        # reqs
        # ruok
        # stat
        s.send(flag)
        data = s.recv(1024)
        s.close()
        if 'Environment' in data:
            info = {
                "url": "zookeeper://{}:{}".format(ip, port),
                "vuln_name": "zookeeper unauthorized access",
                "severity": "high",
                "proof": data
            }
            return info
    except:
        pass

    return None



if __name__ == '__main__':
    main()
