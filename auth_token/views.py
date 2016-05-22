# -*- coding:utf-8 -*-
from base64 import b64decode
import json
from django.contrib.auth import authenticate
from django.contrib.auth.views import login
from django.shortcuts import render, render_to_response,HttpResponse, redirect
from django.contrib.auth.models import User
from django.template.context_processors import csrf
from django.views.decorators.csrf import csrf_exempt
from tokenapi.views import token_new
from django.db import IntegrityError
from tokenapi.decorators import token_required
from redisutil import get_userpk,delete_token,insert_token
from tokens import user_signer,make_token_in_cache,check_token_in_cache

# @token_required
def loginview(request):
    # c = {"yin":"yin"}
    # c.update(csrf(request))
    basic_auth = request.META.get('HTTP_AUTHORIZATION')
    # print basic_auth
    return render(request,'login.html')
    # return render_to_response('login.html', c,)

def auth(request):
    result =  token_new(request)
    return result

#注册
def signup(request):
    data={}
    if request.method == "POST":
        username = request.POST.get('username',None)
        password = request.POST.get('password',None)
        if not (username and password):
            # print request.body
            request_data= json.loads(request.body)
            username =  request_data["username"]
            password =  request_data["password"]
            email =request_data['email']
            if username and password and email:
                try:
                    user = User.objects.get_by_natural_key(username)
                except User.DoesNotExist:
                    user = User.objects.create_user(username,email,password=password)
                    if user.is_active:
                        return HttpResponse("success")
                    else:

                        return HttpResponse("fail")
                else:
                    return HttpResponse("User already exists")


            # print request_data
            # return HttpResponse(request.body,content_type="application/json")
            # print request_data
        # print username,password
        # data['username']=username
        # data['password']=password
        # return HttpResponse(json.dumps(data),content_type="application/json")

    return HttpResponse("signup fail")


#用户密码登录返回token
def login_from_pwd(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
    # username="yzs"
    # password="pwd"
        if username and password:
            user = authenticate(username=username,password=password)

            if user and user.is_active:
                login(request,user)
                token = make_token_in_cache(user).split(":",1)[1]

                #将{token:id}放在redis内
                redis_data = {
                    'token':token,
                    'userpk':user.pk,
                }
                insert_token(redis_data)
                #将pk加密
                userpk = user_signer.sign(user.pk).split(":",1)[1]

                data = {
                    'token':token,
                    'userpk':userpk,
                }
                return HttpResponse(json.dumps(data),content_type="application/json")
            else:
                return HttpResponse("Fail")

from decorators import token_cache_required

@token_cache_required
# @csrf_exempt
def test(request):
    # basic_auth = request.META.get('HTTP_AUTHORIZATION')
    # userpk = request.POST.get('userpk', request.GET.get('userpk'))
    # token = request.POST.get('token', request.GET.get('token'))
    # print userpk,token
    # if not (userpk and token) and basic_auth:
    #         auth_method, auth_string = basic_auth.split(' ', 1)
    #
    #         if auth_method.lower() == 'basic':
    #             auth_string = b64decode(auth_string.strip())
    #             userpk, token = auth_string.decode().split(':', 1)
    # if not (userpk and token):
    #     # print request.body
    #     request_data= json.loads(request.body)
    #     userpk = request_data['userpk']
    #     token = request_data['token']
    # print userpk,token
    # us = None
    # pw = None
    # print request.method
    # if request.method == 'POST':
    #     print "POST"
    #     # print request.META
    #     print request.POST
    #     us = request.POST.get('userpk')
    #     pw = request.POST.get('token')
    # print us,pw
    return HttpResponse("token login succeed")
    # data={
    #     "token": "1b46US:_uw-1cM6p3M8H10r7SF3DR6EQCk",
    #     "userpk": "FgsrjCxMETo6hgMNoeR8Tufa1-o",
    # }
    # return check_token_in_cache(data)

    #
    # """
    # 测试密码登陆
    # """
    # if request.method == 'POST':
    #     username = request.POST.get('username')
    #     password = request.POST.get('password')
    # username="yzs"
    # password="pwd"
    # if username and password:
    #     user = authenticate(username=username,password=password)
    #
    #     if user and user.is_active:
    #         login(request,user)
    #         token = make_token_in_cache(user).split(":",1)[1]
    #
    #         #将{token:id}放在redis内
    #         redis_data = {
    #             'token':token,
    #             'userpk':user.pk,
    #         }
    #         insert_token(redis_data)
    #         #将pk加密
    #         userpk = user_signer.sign(user.pk).split(":",1)[1]
    #
    #         data = {
    #             'token':token,
    #             'userpk':userpk,
    #         }
    #         return HttpResponse(json.dumps(data),content_type="application/json")
    #     else:
    #         return HttpResponse("Fail")


def createUser(**kwargs):
    username = kwargs['username']
    password = kwargs['password']
    email = kwargs['email']
    try:
        user = User.objects.create_user(username,email,password)
    except IntegrityError:
        HttpResponse("Fail")
    # if user.







#
#
# def auth_and_login(request, onsuccess='/secure', onfail='/login/'):
#     user = authenticate(username=request.POST['email'], password=request.POST['password'])
#     if user is not None and user.is_active:
#         login(request, user)
#         request.session['name'] = "yin"
#         return redirect(onsuccess)
#     else:
#         return redirect(onfail)
#
# def create_user(username, email, password):
#     user = User(username=username, email=email)
#     user.set_password(password)
#     user.save()
#     return user
#
# def user_exists(username):
#     user_count = User.objects.filter(username=username).count()
#     if user_count == 0:
#         return False
#     return True
#
# def sign_up_in(request):
#     post = request.POST
#     if not user_exists(post['email']):
#         user = create_user(username=post['email'], email=post['email'], password=post['password'])
#         return auth_and_login(request)
#     else:
#         return redirect("/login/")