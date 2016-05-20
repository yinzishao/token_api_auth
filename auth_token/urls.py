#!/usr/bin/env python
# -*- coding:utf-8 -*-
from django.conf.urls import url

__author__ = 'yinzishao'


urlpatterns = [
    url(r'^login/','auth_token.views.loginview',name='loginview'),
    url(r'^signup/','auth_token.views.signup',name='signup'),
    url(r'^auth/','auth_token.views.auth',name='auth'),
    url(r'^test/','auth_token.views.test',name='test'),
    # url(r'^token/new.json$', token_new, name='api_token_new'),
    # url(r'^token/(?P<token>.{24})/(?P<user>\d+).json$', token, name='api_token'),
]
