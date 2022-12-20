from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import get_user_model


class CustomAuthentication(JWTAuthentication):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_model = get_user_model()

    def authenticate(self, request):
        authorization_header = request.headers.get('Authorization')
        access_token = authorization_header.split(' ')[1]
        validated_token = self.get_validated_token(access_token)
        return self.get_user(validated_token), validated_token
