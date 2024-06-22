from django.urls import path, register_converter

from utils.converters import UUIDConverter
from . import views

register_converter(UUIDConverter, 'uuid')

urlpatterns = [
    # 图形验证码
    path('image_codes/<uuid:uuid>/', views.ImageCodeView.as_view()),
]
