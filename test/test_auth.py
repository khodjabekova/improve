from rest_framework import status
from rest_framework.test import APIClient


class TestCreateCollection:
    def test_wrong_login_or_password_returns_403(self):
        client = APIClient()
        response = client.post(
            '/api/accounts/login/', {'login': 'test', 'password': 'test'})
        assert response.status_code == status.HTTP_403_FORBIDDEN
