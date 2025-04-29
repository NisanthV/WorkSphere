import jwt
from django.http import JsonResponse
from rest_framework import status
from .models import User


class TokenCheckMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        result = self.checkJWT(request)
        if isinstance(result, JsonResponse):
            return result

        response = self.get_response(request)

        return response

    def checkJWT(self, request):

        token = request.COOKIES.get('jwt')

        if not token:
            request.user = None
            return

        try:
            payload = jwt.decode(token, 'secure', algorithms=['HS256'])
        except jwt.ExpiredSignatureError as e:
            response = JsonResponse({"data": f"session expired {e}"}, status=status.HTTP_403_FORBIDDEN)
            response.delete_cookie('jwt')
            return response

        user = User.objects.filter(id=payload['id']).first()

        if not user:
            response = JsonResponse({"data": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            response.delete_cookie('jwt')
            return response

        request.user = user
        return request
