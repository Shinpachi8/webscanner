#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import socket
import subprocess
import os
import time

def check(ip, port, service):
    if port in ['1090', '1099'] or service in ['rmiregistry', 'ff-fms']:
        return True
    return False

def proc_shell(cmd,timeout=10,shell=False):
    proc = subprocess.Popen(cmd,stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell)
    proc.stdin.write('q\n')
    proc.stdin.flush()
    start_time = time.time()
    while True:
        if proc.poll() == None:
            if time.time() - start_time > timeout:
                proc.terminate()
                proc.kill()
                proc.wait()
                return ''
            else:
                time.sleep(1)
        else:
            return proc.communicate()[0]

def verify(ip, port=80, name='', timeout=10, types='ip'):
    if types != 'ip':
        return

    try:
        tools_path = os.path.dirname(os.path.abspath(__file__)) + '/../tools/attackRMI.jar'
        cmd = '/usr/bin/java -jar {0} {1} {2}'.format(tools_path, ip, port).split(' ')
        data = proc_shell(cmd)
        if 'Success' in data:
            info = {
                'url': 'rmi://{}:{}'.format(ip, port),
                'severity': 'high',
                'vuln_name': 'rmi unserialized',
                'proof': ' '.join(cmd)
            }
            info = data.splitlines()[0] + '\n' + data.splitlines()[1]
            details = 'RMI Unserialize CMD  {0}:{1}\n{2}'.format(ip, port, info)
            target = '%s://%s:%s' % ('rmi', ip, port)
            return info
    except Exception, e:
        print e
        pass
