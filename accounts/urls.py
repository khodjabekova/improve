from django.urls import path
from django.urls.conf import include

from . import views

urlpatterns = [

    path('login/', views.LoginView.as_view(), name="login"),
    path('refresh-token/', views.RefreshView.as_view(), name="refresh"),
    path('logout/', views.logout_view, name="logout"),
    path('whoAmI/', views.WhoAmIView.as_view(), name="whoAmI"),


]
