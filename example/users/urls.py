from django.urls import path

from users.views import MeAPIView

urlpatterns = [
    path("me/", MeAPIView.as_view()),
]
