from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.views import View
from django import http

import json
import re

from apps.users.models import User


class LogoutView(View):
    """退出登录"""

    def get(self, request):
        """实现退出登录逻辑"""
        # 清理session
        logout(request)
        # 退出登录，重定向到登录页
        response = JsonResponse({'code': 0,
                                 'errmsg': 'ok'})
        # 退出登录时清除cookie中的username
        response.delete_cookie('username')

        return response


class LoginView(View):
    def get(self, request):

        return render(request, 'login.html')

    def post(self, request):
        # 1.接收参数
        dict = json.loads(request.body.decode())
        username = dict.get('username')
        password = dict.get('password')
        remembered = dict.get('remembered')

        if re.match('^1[3-9]\d{9}$', username):
            # 手机号
            User.USERNAME_FIELD = 'mobile'
        else:
            # account 是用户名
            # 根据用户名从数据库获取 user 对象返回.
            User.USERNAME_FIELD = 'username'

        # 2.校验(整体 + 单个)
        if not all([username, password]):
            return JsonResponse({'code': 400,
                                 'errmsg': '缺少必传参数'})

        # 3.验证是否能够登录
        user = authenticate(username=username,
                            password=password)

        # 判断是否为空,如果为空,返回
        if user is None:
            return JsonResponse({'code': 400,
                                 'errmsg': '用户名或者密码错误'})

        # 4.状态保持
        login(request, user)

        # 5.判断是否记住用户
        if not remembered:
            # 7.如果没有记住: 关闭立刻失效
            request.session.set_expiry(0)
        else:
            # 6.如果记住:  设置为两周有效
            request.session.set_expiry(None)

        response = JsonResponse({'code': 0, 'errmsg': '注册成功!'})
        # 8.返回json
        response.set_cookie('username', user.username, max_age=3600 * 24 * 15)
        return response


# 用户名重复
class UsernameCountView(View):
    def get(self, request, username):
        count = User.objects.filter(username=username).count()
        return JsonResponse({'code': 0, 'errmsg': 'ok', 'count': count})


# 手机号重复

class MobileCountView(View):

    def get(self, request, mobile):
        count = User.objects.filter(mobile=mobile).count()
        return JsonResponse({'code': 0, 'errmsg': 'OK', 'count': count})


class RegisterView(View):

    def post(self, request):
        print("?")
        # 获取数据
        json_bytes = request.body  # 从请求体中获取原始的JSON数据，bytes类型的
        json_str = json_bytes.decode()  # 将bytes类型的JSON数据，转成JSON字符串
        json_dict = json.loads(json_str)
        # 提取
        username = json_dict.get('username')
        password = json_dict.get('password')
        password2 = json_dict.get('password2')
        mobile = json_dict.get('mobile')
        allow = json_dict.get('allow')
        sms_code = json_dict.get('sms_code')

        # 判断
        if not all([username, password, password2, mobile, allow]):
            return http.JsonResponse({'code': 400, 'errmsg': '缺少必传参数!'})
        # 判断用户名是否是5-20个字符
        if not re.match(r'^[a-zA-Z0-9_]{5,20}$', username):
            return http.JsonResponse({'code': 400, 'errmsg': 'username格式有误!'})
        # 判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return http.JsonResponse({'code': 400, 'errmsg': 'password格式有误!'})
        # 判断两次密码是否一致
        if password != password2:
            return http.JsonResponse({'code': 400, 'errmsg': '两次输入不对!'})
        # 判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.JsonResponse({'code': 400, 'errmsg': 'mobile格式有误!'})
        # 判断是否勾选用户协议
        if not allow:
            return http.JsonResponse({'code': 400, 'errmsg': 'allow格式有误!'})

        # 写入数据库

        try:
            user = User.objects.create_user(username=username,
                                            password=password,
                                            mobile=mobile)
        except Exception as e:
            return http.JsonResponse({'code': 400, 'errmsg': '注册失败!'})

        login(request, user)
        response = JsonResponse({'code': 0, 'errmsg': '注册成功!'})

        response.set_cookie('username', user.username, max_age=3600 * 24 * 15)
        return response
