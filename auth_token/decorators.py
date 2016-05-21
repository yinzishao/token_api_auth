#!/usr/bin/env python
# -*- coding:utf-8 -*-
from django.http.response import HttpResponseForbidden

__author__ = 'yinzishao'
from base64 import b64decode

from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from functools import wraps

def token_cache_required(view_func):
    @csrf_exempt
    @wraps(view_func)
    def _wrapped_view(request,*args,**kwargs):
        userpk = None
        token = None
        basic_auth = request.META.get('HTTP_AUTHORIZATION')
        userpk = request.POST.get('userpk', request.GET.get('userpk'))
        token = request.POST.get('token', request.GET.get('token'))
        if not (userpk and token) and basic_auth:
            auth_method, auth_string = basic_auth.split(' ', 1)

            if auth_method.lower() == 'basic':
                auth_string = b64decode(auth_string.strip())
                userpk, token = auth_string.decode().split(':', 1)
        if not (userpk and token):
            return HttpResponseForbidden("Must include 'userpk' and 'token' parameters with request.")
        user = authenticate(pk=userpk, token=token)
        if user:
            request.user = user
            return view_func(request, *args, **kwargs)
        return HttpResponseForbidden()
    return _wrapped_view