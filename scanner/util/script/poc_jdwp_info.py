#!/usr/bin/env python
# coding=utf-8


import socket


def verify(ip, port=8000, name='', types='ip'):
    if types != 'ip':
        return
    
    handshake = 'JDWP-Handshake'
    info = {
            "url": 'jdwp://{}:{}'.format(ip, port),
            'vuln_name': 'jdwp connect',
            'severity': 'high',
            'proof': 'jdb {}:{}'.format(ip, port)
            }
    try:
        soc = socket.create_connection((ip, int(port)), timeout=5)
        soc.send(handshake)
        if soc.recv(len(handshake)) == handshake:
            return info
    except Exception as e:
        pass
    finally:
        soc.close()
