
from django.conf import settings
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.middleware import csrf
from drf_yasg.utils import swagger_auto_schema
from rest_framework import generics
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.exceptions import AuthenticationFailed

from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from . import serializers
from .models import CustomUser


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh_token': str(refresh),
        'access_token': str(refresh.access_token),
    }


# Create your views here.
class LoginView(generics.GenericAPIView):
    permission_classes = [AllowAny, ]
    authentication_classes = []
    serializer_class = serializers.UserLoginSerializer

    def post(self, request, format=None):
        data = request.data
        response = Response()
        username = data.get('username', None)
        password = data.get('password', None)
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                data = get_tokens_for_user(user)
                # response.set_cookie(
                #     key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                #     value=data["access_token"],
                #     expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                #     # max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_MAX_AGE'],
                #     secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                #     httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                #     samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                # )
                response.set_cookie(
                    settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                    data["refresh_token"],
                    httponly=True,
                    expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                    # max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_MAX_AGE'],
                )
                csrf.get_token(request)
                response.data = {"access_token": data["access_token"]}

                return response
            else:
                return Response({"No active": "This account is not active!!"}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({"message": "Invalid username or password!!"}, status=status.HTTP_403_FORBIDDEN)


class RefreshView(APIView):
    permission_classes = [AllowAny, ]
    authentication_classes = []

    def get(self, request, format=None):
        refresh_token = request.COOKIES.get(
            settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        if refresh_token is None:
            raise AuthenticationFailed(
                'Authentication credentials were not provided.')

        token = RefreshToken(refresh_token)
        response = Response()
        response.data = {"access_token": str(token.access_token)}
        return response


@api_view(['GET'])
@authentication_classes([])
@permission_classes([])
def logout_view(request):
    response = JsonResponse({'message': 'Logged out'})
    for cookie in request.COOKIES:

        response.delete_cookie(cookie)
    return response


class WhoAmIView(APIView):
    permission_classes = [IsAuthenticated]
    serializers = serializers.UserSerializer

    def get(self, format=None):
        serializer = serializers.UserSerializer(self.request.user)
        return Response(serializer.data)
