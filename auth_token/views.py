# -*- coding:utf-8 -*-
import json
from django.contrib.auth import authenticate
from django.contrib.auth.views import login
from django.shortcuts import render, render_to_response,HttpResponse, redirect
from django.contrib.auth.models import User
# Create your views here.
from django.template.context_processors import csrf
from tokenapi.views import token_new
from django.db import IntegrityError

from tokenapi.decorators import token_required
# @token_required
def loginview(request):
    # c = {"yin":"yin"}
    # c.update(csrf(request))
    basic_auth = request.META.get('HTTP_AUTHORIZATION')
    print basic_auth
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

    return HttpResponse("No post")

def test(requset):
    username="yzs"
    password="pwd"
    # User.objects.
    if username:
        try:
            user = User.objects.get_by_natural_key(username)
        except User.DoesNotExist:
            user = User.objects.create_user(username,"yz",password=password)
            if user.is_active:
                return HttpResponse("success")
            else:

                return HttpResponse("fail")

        else:
            return HttpResponse("User already exists")
#
    # try:
    #     pass
    # except IntegrityError:
    #     return HttpResponse("Fail")
    # else:
    #     if user:
    #         return HttpResponse("succeed")
    #     else:
    #         return HttpResponse("fail")

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