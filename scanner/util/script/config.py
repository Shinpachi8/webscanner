#!/usr/bin/env python
# coding=utf-8

import socket

def is_port_open(func):
    # soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # socket.settimeout(3.0)
    def wrapper(*args, **kw):

        open = False
        try:
            ip = args[0]
            port = kw["port"] if "port" in kw else "80"
            soc = socket.create_connection((ip, int(port)), timeout=1.5)
            open = True
            soc.close()
        except Exception as e:
            print "[is_port_open] [error={}]".format(repr(e))

        if open:
            func(*args, **kw)
        else:
            return

    return wrapper



def is_http(ip, port):
    http = False
    try:
        a = socket.create_connection((ip, port), timeout=5)
        a.send('GET / HTTP/1.1\r\n\r\n')
        data = a.recv(30)
        if "HTTP" in data:
            http = True
        return http
    except Exception as e:
        pass
    finally:
        a.close()


# TODO: ADD PASSWORD_DIC
