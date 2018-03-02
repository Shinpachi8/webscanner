#!/usr/bin/env python
# -*- coding: utf-8 -*-

from dummy import *

def assign(service, arg):
    if service == "shopex":
        return True, arg

def audit(arg):
    for d in ['app/dev/', 'install/']:
        url = arg + d + 'svinfo.php?phpinfo=true'
        _, _, res, _, _ = hackhttp.http(url)
        if res and res.find('<title>phpinfo()</title>') != -1:
            security_info(url)
            break


if __name__ == '__main__':
    from dummy import *
    audit(assign('shopex', 'http://www.finialshop.com/')[1])
