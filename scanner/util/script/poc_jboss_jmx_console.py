#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from config import *

def check(site, _dir, app, lang):
    if 'jboss' in app.split(','):
        return True
    return False

def verify(ip, port=80, name='', timeout=10, types='ip'):

    if types == 'ip':
        url = ip + ':' + str(port)
    else:
        url = ip
    if not url.startswith('http:/') or not url.startswith('https:/'):
        url = 'http://' + url

    try:
        url = url.rstrip('/') + '/jmx-console/'
        code, head, html = http_request_get(url)
        auths = head.get('WWW-Authenticate','')
        if 'JBoss JMX Console' in auths or 'HtmlAdaptor' in html:
            details = 'JBoss jmx-console Found %s' % (url)
            # target = site + _dir
            info = {
                'url': url,
                'vuln_name': 'jboss console',
                'severity': 'medium',
                'proof': 'JBoss JMX Console in response'
            }
            return info
    except Exception, e:
        pass
