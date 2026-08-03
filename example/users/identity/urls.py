from django.urls import path

from users.identity.views import (
    LoginAPIView,
    LogoutAllAPIView,
    LogoutAPIView,
    RefreshAPIView,
)

urlpatterns = [
    path("auth/login/", LoginAPIView.as_view()),
    path("auth/refresh/", RefreshAPIView.as_view()),
    path("auth/logout/", LogoutAPIView.as_view()),
    path("auth/logout-all/", LogoutAllAPIView.as_view()),
]
