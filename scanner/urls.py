#!/usr/bin/env python
# coding = utf-8

from django.conf.urls import url
from django.contrib.auth.views import  (login,
                                    logout,
                                    password_reset,
                                    password_reset_done,
                                    password_reset_confirm,
                                )
from django.contrib.auth import views as auth_views
# from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    url(r'^$', views.index, name="index"),
    # url('^', include('django.contrib.auth.urls')),
    url(r'^login/$', login, {'template_name':'login.html'}, name ="login"),
    url(r'^logout/$', logout, {'template_name':'logout.html', "next_page": "/"}, name ="logout"),
    url(r'^create/$', views.create, name="create"),
    url(r'^createtask/$', views.createtask, name="createtask"),
    url(r'^showdomainip/$', views.showdomainip, name="showdomainip"),
    url(r'^domains/$', views.domains, name="domains"),
    url(r'^scandomain$', views.scandomain, name="domains"),
    url(r'^nmapscan$', views.nmapscan, name="nmapscan"),
    url(r'^updatehttptitle$', views.updatehttptitle, name="updatehttptitle"),
    url(r'^showvulns$', views.showvulns, name="showvulns"),
    url(r'^deleteopt$', views.deleteopt, name="deleteopt"),
    url(r'^guesscms$', views.guesscms, name="guesscms"),
    url(r'^encode$', views.encode, name="encode"),
    url(r'^search$', views.search, name="search"),
    url(r'^portcrack$', views.search, name="portcrack"),
]
