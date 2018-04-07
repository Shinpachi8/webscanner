# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
#
# Also note: You'll have to insert the output of 'django-admin sqlcustom [app_label]'
# into your database.
from __future__ import unicode_literals

from django.db import models


class AuthGroup(models.Model):
    name = models.CharField(unique=True, max_length=80)

    class Meta:
        managed = False
        db_table = 'auth_group'


class AuthGroupPermissions(models.Model):
    group = models.ForeignKey(AuthGroup)
    permission = models.ForeignKey('AuthPermission')

    class Meta:
        managed = False
        db_table = 'auth_group_permissions'
        unique_together = (('group', 'permission'),)


class AuthPermission(models.Model):
    name = models.CharField(max_length=255)
    content_type = models.ForeignKey('DjangoContentType')
    codename = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'auth_permission'
        unique_together = (('content_type', 'codename'),)


class AuthUser(models.Model):
    password = models.CharField(max_length=128)
    last_login = models.DateTimeField(blank=True, null=True)
    is_superuser = models.IntegerField()
    username = models.CharField(unique=True, max_length=30)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email = models.CharField(max_length=254)
    is_staff = models.IntegerField()
    is_active = models.IntegerField()
    date_joined = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'auth_user'


class AuthUserGroups(models.Model):
    user = models.ForeignKey(AuthUser)
    group = models.ForeignKey(AuthGroup)

    class Meta:
        managed = False
        db_table = 'auth_user_groups'
        unique_together = (('user', 'group'),)


class AuthUserUserPermissions(models.Model):
    user = models.ForeignKey(AuthUser)
    permission = models.ForeignKey(AuthPermission)

    class Meta:
        managed = False
        db_table = 'auth_user_user_permissions'
        unique_together = (('user', 'permission'),)


class DjangoAdminLog(models.Model):
    action_time = models.DateTimeField()
    object_id = models.TextField(blank=True, null=True)
    object_repr = models.CharField(max_length=200)
    action_flag = models.SmallIntegerField()
    change_message = models.TextField()
    content_type = models.ForeignKey('DjangoContentType', blank=True, null=True)
    user = models.ForeignKey(AuthUser)

    class Meta:
        managed = False
        db_table = 'django_admin_log'


class DjangoContentType(models.Model):
    app_label = models.CharField(max_length=100)
    model = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'django_content_type'
        unique_together = (('app_label', 'model'),)


class DjangoMigrations(models.Model):
    app = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    applied = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_migrations'


class DjangoSession(models.Model):
    session_key = models.CharField(primary_key=True, max_length=40)
    session_data = models.TextField()
    expire_date = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_session'


class Domain(models.Model):
    domain = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'domain'


class PortTable(models.Model):
    ip = models.CharField(max_length=35, blank=True, null=True)
    port = models.IntegerField(blank=True, null=True)
    protocol = models.CharField(max_length=30, blank=True, null=True)
    name = models.CharField(max_length=150, blank=True, null=True)
    product = models.CharField(max_length=100, blank=True, null=True)
    extrainfo = models.CharField(max_length=100, blank=True, null=True)
    version = models.CharField(max_length=100, blank=True, null=True)
    conf = models.CharField(max_length=100, blank=True, null=True)
    id_domain = models.IntegerField(blank=True, null=True)
    httptitle = models.TextField(blank=True, null=True)
    cmstype = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'port_table'


class Subdomains(models.Model):
    subdomain = models.CharField(max_length=150, blank=True, null=True)
    id_domain = models.IntegerField(blank=True, null=True)
    cmstype = models.CharField(max_length=30, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'subdomains'


class Vulns(models.Model):
    url = models.TextField(blank=True, null=True)
    parameters = models.TextField(blank=True, null=True)
    headers_string = models.TextField(blank=True, null=True)
    method = models.CharField(max_length=15, blank=True, null=True)
    delta_time = models.CharField(max_length=50, blank=True, null=True)
    vuln_name = models.CharField(max_length=150, blank=True, null=True)
    severity = models.CharField(max_length=30, blank=True, null=True)
    checks = models.CharField(max_length=150, blank=True, null=True)
    proof = models.TextField(blank=True, null=True)
    seed = models.TextField(blank=True, null=True)
    id_domain = models.IntegerField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'vulns'
