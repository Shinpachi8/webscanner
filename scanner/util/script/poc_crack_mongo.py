# coding=utf-8
import socket
import binascii
from config import is_port_open


# @is_port_open
def verify(ip, port=27017, name='', timeout=10, types='ip'):
    if types !='ip':
        return
        
    if int(port) != 27017 or "mongo" not in name:
        return
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        data = binascii.a2b_hex(
            "3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000")
        s.send(data)
        result = s.recv(1024)
        if "ismaster" in result:
            getlog_data = binascii.a2b_hex(
                "480000000200000000000000d40700000000000061646d696e2e24636d6400000000000100000021000000026765744c6f670010000000737461727475705761726e696e67730000")
            s.send(getlog_data)
            result = s.recv(1024)
            if "totalLinesWritten" in result:
                info = {
                    "url": "mongo://{}:{}".format(ip, port),
                    "vuln_name": "mongo Unauthorized access",
                    "severity": "medium",
                    "proof": "totalLinesWritten"
                }
                return info
    except Exception, e:
        pass
