#!/usr/bin/env python
# -*- coding:utf-8 -*-
from django.contrib.auth.models import User
from django.http.response import HttpResponse

__author__ = 'yinzishao'

from django.core.signing import Signer,TimestampSigner
from redisutil import get_userpk,delete_token

token_cahce_salt = "make_token_in_cache"
time_signer = TimestampSigner(salt=token_cahce_salt)
user_salt = "user_salt"
user_signer = Signer(salt=user_salt)


#根据id和timestamp生成token
def make_token_in_cache(user):

    userpk = user.pk
    user_str = "userpk"+"-"+str(userpk)
    token = time_signer.sign(user_str)
    return token
    # password =user.password
    # id_pwd=str(userid)+"-"+password
    # value = singer.sign(id_pwd)
        # return HttpResponse(id_pwd)
        # value = singer.sign('token')

#根据token和userpk判断是否出现和篡改
def check_token_in_cache(data):
    token = data['token']
    userpk= data['userpk']
    #过期时间，默认10天
    max_age= 60*60*24*10
    # time_signer.unsign(token)
    userpk_origin = get_userpk(token)
    # print userpk_origin
    if userpk_origin:
        user_str = "userpk"+"-"+str(userpk_origin)
        value = user_str+":"+token
        try:
            time_signer.unsign(value,max_age=max_age)
        except Exception,e:
            # print e.message
            delete_token(token)
            return None,HttpResponse("expired please login in again")
        else:
            userpk_str = str(userpk_origin)+":"+str(userpk)
            # print userpk_str,type(userpk_str),id(userpk_str)
            userpk_sige_str=user_signer.sign(userpk_origin)
            # print userpk_sige_str,type(userpk_sige_str),id(userpk_sige_str)
            if userpk_str ==userpk_sige_str:
                #更新token时间?
                user = User.objects.get(pk=userpk_origin)
                return user,HttpResponse("succeed")
            else:
                return None,HttpResponse("Login in Fail PK ")

    else:
        return None,HttpResponse("Login in Fail")

    #
    # user_str = "userpk"+"-"+str(userpk)
    # value = user_str+":"+token
    # try :
    #     time_signer.unsign(value)
    # except:
    #     return HttpResponse("Token is invalid")
    # else:
    #     return HttpResponse("succeed")

