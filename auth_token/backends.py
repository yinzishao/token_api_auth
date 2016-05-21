#!/usr/bin/env python
# -*- coding:utf-8 -*-
__author__ = 'yinzishao'

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from tokens import check_token_in_cache

class TokenCacheBakcend(ModelBackend):
    def authenticate(self,pk,token):
        data={}
        data["token"]=token
        data["userpk"]=pk
        user,inf=check_token_in_cache(data)
        if user:
            return user
        else:
            return None

