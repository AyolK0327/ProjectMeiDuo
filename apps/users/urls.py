from django.urls import path
from . import views
from django.urls import register_converter
from utils.converters import UsernameConverter, MobileConverter

register_converter(UsernameConverter, 'username')
register_converter(MobileConverter, 'mobile')

urlpatterns = [
    # 判断用户名是否重复
    path('usernames/<username:username>/count/', views.UsernameCountView.as_view()),
    path('mobiles/<mobile:mobile>/count/', views.MobileCountView.as_view()),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.LoginView.as_view())
]
