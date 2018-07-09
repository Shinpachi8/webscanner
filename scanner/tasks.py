#!/usr/bin/env python
# coding=utf-8

import sys
import os
from netaddr import *
from Queue import Queue
from celery import shared_task
from pprint import pprint
from scanner.models import *
from config import *
from commons import *


@shared_task
def create_to_database(ip_cidr, id_domain):
    save_sql = 'insert into port_table (ip, port, id_domain) values (\'{ip}\', 80, \'{id_domain}\')'
    exist_sql = 'select * from port_table where id_domain=\'{id_domain}\' and ip=\'{ip}\''
    if isinstance(ip_cidr, list):
        pass
    else:
        ip_cidr = [ip_cidr,]
    
    conn = MySQLUtils()
    try:
        for ips in ip_cidr:
            ips = IPNetwork(ips)
            for ip in ips:
                data = conn.fetchone(exist_sql.format(ip=pymysql.escape_string(ip), id_domain=id_domain))
                if data:
                    continue
                else:
                    conn.insert(save_sql.format(ip=pymysql.escape_string(str(ip)), id_domain=id_domain))
    except Exception as e:
        logger.error("[tasks] [create_to_database] error for {}".format(repr(e)))
    finally:
        conn.close()

        

@shared_task(routing_key='ipscan.masscan')
def task_masscan(ip_cidr, id_domain, port=None):
    """
    this function aim to use masscan to scan the port,
    :param: ip_cidrs,  the ip cidr ,a string like "127.0.0.1"
    :param: port, the port to scan, can be None
    :rtype: None
    """
    if sys.platform.find("win") > 0:
        mas = os.path.join(MASSCAN_LOC_WIN, "masscan.exe")
    else:
        mas = os.path.join(MASSCAN_LOC, "masscan")

    if port is None:
        port = TARGET_PORTS

    command = "{mas} {ip_cidr} -p {port} --open --banners --rate 2000 -oX -".format(mas=mas, ip_cidr=ip_cidr, port=port)

    content = masscan_work(command)
    #print "masscan_result = {}".format(content)

    if content:

        x = parse_masscan_xml(content)  # (ip, port, name, banner)
        s = MySQLUtils()
        check_exist_sql = "select * from port_table where ip='{ip}' and port='{port}' and id_domain='{id_domain}'"
        update_masscan_sql = "update port_table set name='{name}', product='{banner}' where id={id}"
        insert_masscan_sql = "insert into port_table (ip, port, name, product, id_domain) values ('{ip}', '{port}', '{name}', '{product}', '{id_domain}')"
        for item in x:
            ip, port, name, banner = item
            try:
                data = s.fetchone(check_exist_sql.format(ip=pymysql.escape_string(ip), port=pymysql.escape_string(port), id_domain=id_domain))
                if data:
                    s.insert(update_masscan_sql.format(name=pymysql.escape_string(name), banner=pymysql.escape_string(banner), id=data[0]))
                else:
                    s.insert(insert_masscan_sql.format(ip=pymysql.escape_string(ip), port=pymysql.escape_string(port), name=pymysql.escape_string(name), product=pymysql.escape_string(banner), id_domain=id_domain))
            except Exception as e:
                logger.error("save masscan error for reason={}".format(repr(e)))
        s.close()



        # save_masscan_result_to_porttable(x, id_domain)



@shared_task(routing_key='ipscan.nmap2')
def nmap_scan2(ip_cidr, id_domain):
    ip_cidr = IPNetwork(ip_cidr)
    for ip in ip_cidr:
        ip = str(ip)
        nmap_scan.delay(ip, id_domain)


@shared_task(routing_key='ipscan.nmap3')
def nmap_scan3(id_domain):
    ipobjs = PortTable.objects.values("ip").filter(id_domain=id_domain).distinct()
    id_domain = int(id_domain)
    for ip in objs:
        ip = ip['ip']
        nmap_scan.delay(ip, id_domain)


@shared_task(routing_key='ipscan.nmap')
def nmap_scan(ip, id_domain):
    """
    (host          0;
    hostname       1;
    hostname_type  2;
    protocol       3;
    port           4;
    name           5;
    state          6;
    product        7;
    extrainfo      8;
    reason         9;
    version        10;
    conf           11;
    cpe            12)
    """
    #resultqueue = Queue()
    #nmap_work(ipportqueue, resultqueue, id_domain)
    # portobjs = PortTable.objects.filter(id_domain=id_domain)
    # portqueue = set()
    # id_domain = int(id_domain)
    # for obj in portobjs:
    #     o = (obj.ip, obj.port)
    #     portqueue.add(o)
    
    # portqueue=list(portqueue)
    
    nmap_work(ip, id_domain)


@shared_task(time_limit=600)
def sensitivescan(ip, port, id_domain):

    try:
        # scanobj = InfoLeakScanGevent(url)
        scheme = ''
        if is_https(ip, port) == 'https':
            scheme = 'https'
        elif is_http(ip, port) == 'http':
            scheme = 'http'
        else:
            return
        url = "{}://{}:{}".format(scheme, ip, port)
        scanobj = InfoLeakScan(url)
        scanobj.scan()
        result = scanobj.result
        count = 0
        print "[sensitive_task] [url={}] [result.qsize] = {}".format(url, result.qsize())
        insert_vuln_sql = 'insert into vulns (id_domain, url, vuln_name, severity) values ("{id_domain}", "{url}", "{vuln_name}", "{severity}")'
        while not result.empty():
            if count > 10:
                result.queue.clear()
                break
            url = result.get()
            vuln_name = "sensitive infomation"
            save2sql(insert_vuln_sql.format(id_domain=id_domain, url=pymysql.escape_string(url), vuln_name=pymysql.escape_string(vuln_name), severity='low'))
            # save_vuln_to_db(id_domain, url, vuln_name, severity="low")
            count += 1
    except Exception as e:
        logger.error("[sensitive_task] [error={}]".format(repr(e)))




@shared_task(time_limit=3000)
def pocverify(id_domain):
    """
    this is aim to use script to scan th ip address to detect
    like unauth or ms17_10 vulnerability
    :param: ipcidr like 127.0.0.1/24
    :rtype: None
    """
    portobjs = PortTable.objects.filter(id_domain=id_domain).values_list('ip', 'port', 'name', 'cmstype')
    urlqueue = Queue()
    for obj in portobjs[:200]:
        urlqueue.put(obj)
    pocscan(urlqueue)

@shared_task(time_limit=6000)
def get_title(portobjlist):
    """
    the celery task deal the http title task
    :param: portobjlist = [(ip, port, id_domain)]
    """
    #fetch_title(portobjlist)
    fetch_title(portobjlist)



@shared_task(time_limit=3000)
def CMSGuess(id_domain, isip):
    urlqueue = Queue()
    if isip:
        objs = PortTable.objects.filter(id_domain=id_domain).filter(cmstype__isnull=True)
        for o in objs:
            #if is_http(o.ip, o.port) == 'http':
            _x = ('{}:{}'.format(o.ip, o.port), o.id, isip)
            urlqueue.put(_x)

    else:
        urlobjs = Subdomains.objects.filter(id_domain=id_domain).filter(cmstype__isnull=True)
        for o in urlobjs:
            _x = (o.subdomain, o.id, isip)
            urlqueue.put(_x)
    cms_guess(urlqueue)


@shared_task
def portCrack(id_domain):
    sql = "select port,ip,service from port_table where id_domain={} and service in ('ftp', 'mysql', 'mssql', 'redis', 'vnc', 'ssh', 'postgres','rdp', 'telnet')"
    
    insert_vul_sql = "insert into vulns (url, vuln_name, severity, proof, id_domain) values ('{}', 'WeakPassword', 'High', '{}', '{}')"
    conn = MySQLUtils()
    try:
        data = conn.fetchall(sql.format(id_domain))
        conn.close()
        # queue, result_queue = Queue(), Queue()
        for item in data:
            # port, ip, service = item
            try:
                vul_list = crackWork(item)
                if vul_list:
                    t_conn = MySQLUtils()
                    for i in vul_list:
                        t_conn.insert(insert_vul_sql.format(i, i, id_domain))
                    t_conn.close()
            except:
                pass
        
        # crackWork(queue, result_queue)
        # save to database
    except Exception as e:
        logger.error('[portCrack] error: {}'.format(repr(e)))
    finally:
        try:
            conn.close()
        except:
            pass
        


if __name__ == '__main__':
    a = [
        ('106.38.219.16', '80', '', ''),
        ('106.38.219.49', '80', '', ''),
        ('106.38.219.49', '80', '', ''),
        ('106.38.219.75', '873', '', ''),
        ('106.38.219.75', '873', '', ''),
        ('106.38.219.43', '443', '', ''),

    ]
    # p  = Queue()
    # for i in a:
    #     p.put(i)

    # nmap_scan(p, "1")
    task_masscan(["106.38.219.43/26",], "1")
