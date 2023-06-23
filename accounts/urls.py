from django.urls import path
from .views import UserCreateView, ProfileView, LoginView, RefreshTokenView

urlpatterns = [
    path('login/', LoginView.as_view()),
    path('refresh/', RefreshTokenView.as_view()),
    path('profile/', ProfileView.as_view()),
    path('create/', UserCreateView.as_view()),
]
