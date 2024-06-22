from django.http import JsonResponse
from django.views import View

from apps.users.models import User


# Create your views here.
class UsernameCountView(View):
    def get(self, request, username):

        count = User.objects.filter(username=username).count()
        return JsonResponse({'code': 0, 'errmsg': 'ok', 'count': count})


class MobileCountView(View):

    def get(self, request, mobile):

        count = User.objects.filter(mobile=mobile).count()
        return JsonResponse({'code': 0, 'errmsg': 'OK', 'count': count})
