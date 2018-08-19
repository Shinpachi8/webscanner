# -*- coding: utf-8 -*-
from __future__ import unicode_literals

# from django.shortcuts import render


import random
from django.shortcuts import render
from django.http import Http404
from django.shortcuts import render_to_response
from django.shortcuts import redirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.http import JsonResponse
from django.http import HttpResponse
from django.http import StreamingHttpResponse
from django.template import RequestContext
from django.http import HttpResponseRedirect
from django.core.files.base import ContentFile
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import reverse
from django.db.models import Q
from django.core.paginator import Paginator
from netaddr import IPNetwork
from cgi import escape
from tasks import task_masscan, nmap_scan, nmap_scan2, nmap_scan3, get_title, sensitivescan, pocverify, CMSGuess, create_to_database
from tasks import save_masscan_result_to_porttable
from models import *
from commons import *


# Create your views here.

@login_required(login_url='/login/')
def index(request):
    print "request.user= {}".format(request.user.username)
    #print dir(request.user)
    return render(request, "index.html")

@login_required(login_url='/login/')
def create(request):
    return render(request, "create.html")

@login_required(login_url='/login/')
def createtask(request):
    """
    this function aim to create task, i.e. add url and ips to database
    but on test, it's vaste lots of time .
    so next version, consider use celery to do the work
    """
    if request.method != "POST":
        raise Http404("Only POST Support")
    domain = request.POST["domain"]
    if not domain:
        raise Http404("domain required!")

    #judge if the domain in databases, if not save it to database
    domain_obj, created = Domain.objects.get_or_create(domain=domain)

    # get id_domain
    id_domain = domain_obj.id


    ips = request.POST.get("ips", '')
    files = request.FILES.get("files", "")
    filecontent = request.POST.get('filecontent', 'subip')
    ip_cidr = []
    if files:
        if filecontent == 'subip':
            content = files.readlines()
            save_masscan_result_to_porttable.delay(content, id_domain)
            del files
        elif filecontent == 'subdomain':
            content = [i.strip() for i in files.readlines() if i.strip()]
            for url in content:
                subdomain_obj, created = Subdomains.objects.get_or_create(
                    subdomain=url,
                    id_domain=id_domain,
                    )
            del files


        # deal files for now ,just think it's subdomainsbrtue result
        # file_content = ContentFile(files.read())
    #     lines = files.readlines()
    #     #print "======"
    #     # print domain
    #     # print lines[0]
    #     urls, iplist = parse_file(lines)
    #     for url in urls:
    #         subdomain_obj, created = Subdomains.objects.get_or_create(
    #             subdomain=url,
    #             id_domain=id_domain,
    #             )

    #     ip_cidr = get_ip_target(iplist)
    if ips:
        ips = ips.split(",")
        for i in ips:
            if i not in ip_cidr:
                ip_cidr.append(i)

        # # create_to_database.delay(ip_cidr, id_domain)

        # #print ip_cidr
        # iplist = []
        try:
            for i in ip_cidr:
                if i:
                    ipnetwork = IPNetwork(i)
                    for ip in ipnetwork:
                        iplist.append(ip)
            random.shuffle(iplist)
            for ip in iplist:
                nmap_scan.delay(str(ip), id_domain)
        #     del iplist
        except Exception as e:
            raise Http404("IP CIDRS MUST BE A LIST BOJECTS")

    return redirect(reverse("index"))
    # first save it to databases and the use masscan to scan


@login_required(login_url='/login/')
def showdomainip(request):
    if "domain" in request.POST:
        domain = request.POST["domain"]
    else:
        domain = None
    if domain:
        domain_id = Domain.objects.get(id=domain)
        domain_id = domain_id.id
    else:
        domain_id = 1
    ip_objects = PortTable.objects.filter(id_domain=domain_id)
    domain_objects = Domain.objects.all()
    # get page
    # split page
    print "domain_id is {}".format(domain_id)
    paginator = Paginator(ip_objects, 20)  # 实例化一个分页对象

    page = request.GET.get('page', '1')  # 获取页码
    page = int(page)
    try:
        ip_objects = paginator.page(page)  # 获取某页对应的记录
    except PageNotAnInteger:  # 如果页码不是个整数
        ip_objects = paginator.page(1)  # 取第一页的记录
    except EmptyPage:  # 如果页码太大，没有相应的记录
        ip_objects = paginator.page(paginator.num_pages)  # 取最后一页的记录

    return render(request, 'showdomainip.html', {'ipobjs': ip_objects, 'domainobjs': domain_objects})


@login_required(login_url='/login/')
def domains(request):
    """
     this function show the domains, i.e.  id<=>domain
     and remains the action like scan, delete and so on
    """
    domainobjs = Domain.objects.all()
    paginator = Paginator(domainobjs, 25)
    page = request.GET.get("page", "1")
    page = int(page)
    try:
        objs = paginator.page(page)
    except PageNotAnInteger:
        objs = paginator.page(1)
    except EmptyPage:
        objs = paginator.page(paginator.num_pages)
    return render(request, "domains.html", {"objs": objs})


@login_required(login_url='/login/')
def scandomain(request):
    try:
        assert "id" in request.GET
    except Exception as e:
        return Http404("error param: {}".format(repr(e)))

    id_domain = request.GET["id"]
    try:
        id_domain = int(id_domain)
    except Exception:
        return Http404("must integer")

    # first get the all subdomains and then
    # use infoleak to scan the info
    subdomains = Subdomains.objects.filter(id_domain=id_domain)
    for s in subdomains:
        #sensitivescan.delay(s.subdomain, id_domain)
        # print "[view] [scandomain] [line160] http={}".format(s.subdomain)
        # sensitivescan.delay(s.subdomain, '80', id_domain)
        pass


    # second get the ip talbes
    portobjs = PortTable.objects.filter(Q(id_domain=id_domain),Q(cmstype__icontains='www')|Q(httptitle__isnull=False)).values_list('ip', 'port', 'name').iterator()
    iplist = set()
    httplist = []
    for obj in portobjs:
        ip, port, name = obj
        #iplist.add(ip)
        #if is_http(ip, port) == 'http':
        #if str(port) in ("443", "8443") or (name.find("https") > -1) or (name.find('ssl') > -1):
        #    h = "https://{}:{}".format(ip, port)
        #else:
        #    h = "http://{}:{}".format(ip, port)
        httplist.append((ip, port))

    for obj in httplist:
    #     # print "[view] [scandomain] [line182] http={}".format(http)
        ip, port = obj
        # sensitivescan.delay(ip, port, id_domain)

    pocverify.delay(id_domain, types='url')
    pocverify.delay(id_domain, types='ip')
    return redirect("/")
    # return HttpResponse("httplist={}\nip_cidr={}".format(httplist, ip_cidr))


@login_required(login_url='/login/')
def nmapscan(request):
    if "id" not in request.GET:
        return redirect("/")
    domainid = request.GET.get("id")
    # portobjs = PortTable.objects.filter(id_domain=domainid)
    # portqueue = set()
    # id_domain = int(domainid)
    # for obj in portobjs:
    #     o = (obj.ip, obj.port)
    #     portqueue.add(o)

    # portqueue=list(portqueue)

    #return HttpResponse(str(portqueue))
    # nmap_scan3.delay(domainid)
    ipobjs = PortTable.objects.values("ip", "port").filter(id_domain=domainid).iterator()
    objs = []
    id_domain = int(domainid)
    count = 0
    for obj in ipobjs:
        ip = obj['ip']
        port = str(obj['port'])
        objs.append((ip, port))
        count += 1
        if count >= 1000:
            nmap_scan.delay(objs, id_domain, port=-1)
            objs = []
            count = 0


    print "total:  {}".format(len(objs))
    nmap_scan.delay(objs, id_domain, port=-1)
    del objs
    return redirect("/")


@login_required(login_url='/login/')
def updatehttptitle(request):
    """
    this function aim to update the http title
    i.e. the fetch the <title>.*</title> or first 200 bytes

    """
    if "id" not in request.GET or (not request.GET["id"].isdigit()):
        return redirect("/")
    id_domain = int(request.GET["id"])
    portobjs = PortTable.objects.filter(id_domain=id_domain).filter(name__icontains='http')
    portobjlist = []
    length = len(portobjs)
    if length < 100:
        N = 1
    else:
        N = 10

    if N == 1:
        for obj in portobjs:
            o = (obj.id, obj.ip, obj.port)
            portobjlist.append(o)

        get_title.delay(portobjlist)
        del portobjlist
    else:
        j = length / N
        k = length % N
        for i in xrange(0, (N-1)*j, j):
            tmp = portobjs[i:i+j]
            task = []
            for obj in tmp:
                o = (obj.id, obj.ip, obj.port)
                task.append(o)
            get_title.delay(task)
            del task
            del tmp
        task = []
        for obj in portobjs[(N-1)*j:]:
            o = (obj.id, obj.ip, obj.port)
            task.append(o)
        get_title.delay(task)
        del task
        del portobjs

    return redirect("/")


@login_required(login_url='/login/')
def showvulns(request):
    if request.method != 'POST':
        return render(request, 'showdomainip2.html')
    if "id_domain" not in request.POST:
        id_domain = 1
    else:
        id_domain = request.GET.get('id_domain')
        try:
            id_domain = int(id_domain)
        except:
            raise Http404("param format error")

    # vulnobj = Vulns.objects.filter(id_domain=id_domain)
    # domainobjs = Domain.objects.all()
    # get page
    # split page
    objs = Vulns.objects.filter(Q(id_domain=id_domain)).values('id', 'url', 'parameters', 'vuln_name', 'severity', 'id_domain')
    return JsonResponse({'result': list(objs)})

    # paginator = Paginator(vulnobj, 20)  # 实例化一个分页对象

    # page = request.GET.get('page', '1')  # 获取页码
    # page = int(page)
    # try:
    #     vulnobj = paginator.page(page)  # 获取某页对应的记录
    # except PageNotAnInteger:  # 如果页码不是个整数
    #     vulnobj = paginator.page(1)  # 取第一页的记录
    # except EmptyPage:  # 如果页码太大，没有相应的记录
    #     vulnobj = paginator.page(paginator.num_pages)  # 取最后一页的记录

    # return render(request, 'vulns.html', {'ipobjs': vulnobj, 'domainobjs': domainobjs})



@login_required(login_url='/login/')
def deleteopt(request):
    # print dir(request)

    try:
        if "id" not in request.GET or "table" not in request.GET:
            raise Http404("parameter error")
        if request.GET["table"] not in ("vulns", "port", "domain"):
            raise Http404("parameter error")
        deleteid = int(request.GET["id"])
        table = request.GET["table"]
        if table == "vulns":
            #print "id={}&table={}".format(deleteid, table)
            Vulns.objects.filter(id=deleteid).delete()
        elif table == "port":
            PortTable.objects.filter(id=deleteid).delete()
        elif table == "domain":
            Domain.objects.filter(id=deleteid).delete()
        else:
            raise Exception("unknow table")
    except Exception as e:
        return Http404("error happend")

    result = {'success':True}
    return JsonResponse(result)


@login_required(login_url='/login/')
def guesscms(request):
    """
    this function aim to invoke the celery function
    to guess cms type.
    if cms type is not null, ingore it
    """
    if ("id" not in request.GET) or (request.GET['id'].isdigit() is False):
        return redirect("/")
    id_domain = int(request.GET['id'])
    # first get the subdomains
    #subdomainobjs = Subdomains.objects.filter(id_domain=id_domain).filter(cmstype__isnull=True)
    # update 18-03-01
    #subdomainobjs = list(subdomainobjs)
    CMSGuess.delay(id_domain, False)
    CMSGuess.delay(id_domain, True)
    #for s in subdomainobjs:
    #    CMSGuess.delay(s.subdomain, s.id, isip=False)

    #ipobjs = PortTable.objects.filter(id_domain=id_domain).filter(cmstype__isnull=True)
    #for ipobj in ipobjs:
        # join ip from ipobj.ip, ipobj.port
    #    _ = '{}:{}'.format(ipobj.ip, ipobj.port)
    #    CMSGuess.delay(_, ipobj.id, isip=True)
    return HttpResponse('alright, we finally got it')

@login_required(login_url='/login/')
def search(request):
    """
    this function aim to use the condition to search some
    data from the databases like domain, port, name, cmstype and other types
    """
    if request.method != 'POST':
        return render(request, 'search.html')

    domain = request.POST.get('domain', '')
    name = request.POST.get('name', '')
    cmstype = request.POST.get('cmstype', '')
    title = request.POST.get('title', '')

    if domain:
        # if domain has value, then get it id form domain
        id_domain = Domain.objects.get(domain__icontains=domain).id
    else:
        id_domain = 1

    objs = PortTable.objects.filter(Q(id_domain=id_domain)).values('id_domain', 'ip', 'port', 'httptitle', 'cmstype', 'name')
    if title:
        objs = objs.filter(httptitle__icontains=title)
    if name:
        objs = objs.filter(name__icontains=name)
    if cmstype:
        objs = objs.filter(cmstype__icontains=cmstype)


    #objs = PortTable.objects.filter(Q(name__icontains=name)&Q(cmstype__icontains=cmstype)&Q(httptitle__icontains=title)&Q(id_domain__icontains=id_domain)).values('id_domain', 'ip', 'port', 'httptitle', 'cmstype', 'name')
    # objs = PortTable.objects.filter(Q(cmstype__icontains=cmstype)|(Q(httptitle__icontains=title)&Q(id_domain=id_domain))).values('id_domain', 'ip', 'port', 'httptitle', 'cmstype', 'name')
    # print objs
    #objs = PortTable.objects.filter(name__icontains=name).filter(cmstype__icontains=cmstype)\
    #    .filter(httptitle__icontains=title)
    return JsonResponse({'result': list(objs)})



@login_required(login_url='/login/')
def portcrack(request):
    if 'id_domain' not in request.GET:
        return Http404('param Error')

    id_domain = request.GET['id_domain']
    if not id_domain.isdigit():
        return Http404('param Error')

    id_domain = int(id_domain)
    portCrack.delay(id_domain)
    return redirect("/")

def encode(requests):
    obj = PortTable.objects.filter(httptitle__isnull=False)
    for o in obj:
        o.httptitle = escape(o.httptitle)
        o.save()

    return HttpResponse('Done')
