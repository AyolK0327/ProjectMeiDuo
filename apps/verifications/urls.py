from django.urls import path
from . import views
from django.urls import register_converter
from utils.converters import UsernameConverter, MobileConverter, UUIDConverter

register_converter(UUIDConverter, 'uuid')

urlpatterns = [
    # 判断用户名是否重复
    path('image_codes/<uuid:uuid>/', views.ImageCodeView.as_view()),
]
