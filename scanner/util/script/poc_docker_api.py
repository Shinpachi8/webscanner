#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from config import *

def check(ip, port, service):
    if port == '2375':
        return True
    return False

def verify(ip, port=80, name='', timeout=10, types='ip'):

    if types == 'ip':
        url = ip + ':' + str(port)
    else:
        url = ip

    info = {
        'url': url,
        'severity': 'high',
        'vuln_name': 'docker remote api',
        'proof': 'command, status, created in response'
    }
    try:
        url = 'http://{0}/containers/json'.format(url)
        code, head, html = http_request_get(url)
        if 'Command' in html and 'Status' in html and 'Created' in html:
            details = 'Docker Remote API  http://%s:%s' % (ip, port)
            target = '%s://%s:%s' % ('docker', ip, port)
            return info
    except Exception, e:
        pass
