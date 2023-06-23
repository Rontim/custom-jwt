from django.conf import settings
import jwt
from .models import UserAccount
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import exceptions
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from django.utils.decorators import method_decorator
from .serializers import UserAccountSerializer
from .utils import generate_access_token, generate_refresh_token
from django.contrib.auth import get_user_model

User = get_user_model()


class UserCreateView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        data = request.data
        email = data['email']
        username = data['username']
        first_name = data['first_name']
        last_name = data['last_name']
        password = data['password']
        re_password = data['re_password']

        if not re_password:
            return Response({'error': 'confirm the password'})

        if password != re_password:
            return Response({'error': 'passwords do not match'})

        if User.objects.filter(email=email).exists():
            return Response({'error': f'User with this email {email} already exist'})

        if User.objects.filter(username=username).exists():
            return Response({'error': f'User with this username {username} already exist'})

        try:
            user = User.objects.create(
                email=email, username=username, first_name=first_name, last_name=last_name, password=password)
        except Exception as e:
            return Response({'error': str(e)})

        if isinstance(user, UserAccount):
            name = user.get_full_name()
            username = user.username
        else:
            name = ''
            username = ''

        return Response({'success': 'User created successfully', 'user': {
            'id': user.pk,
            'email': user.get_username(),
            'username': username,
            'name': name,

        }})


class ProfileView(APIView):
    def get(self, request, format=None):
        user = request.user
        serializer_data = UserAccountSerializer(user).data
        return Response({'user': serializer_data})


@method_decorator(ensure_csrf_cookie, name='dispatch')
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        email = request.data.get('email')
        username = request.data.get('username')
        password = request.data.get('password')

        if (not username and not email) or not password:
            raise exceptions.AuthenticationFailed(
                'email or username and password required')

        user = User.objects.filter(email=email).first(
        ) or User.objects.filter(username=username).filter()

        if user is None:
            raise exceptions.AuthenticationFailed('user not found')

        if not user.custom_check_password(password):  # type: ignore
            raise exceptions.AuthenticationFailed('Passwords do not match')

        serialized_user = UserAccountSerializer(user).data

        access = generate_access_token(user)
        refresh = generate_refresh_token(user)

        response_data = {'access': access, 'user': serialized_user}
        response = Response(response_data)
        response.set_cookie(key='refreshtoken', value=refresh, httponly=True)
        return response


@method_decorator(csrf_protect, name='dispatch')
class RefreshTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):

        refresh_token = request.COOKIES.get('refreshtoken')

        if refresh_token is None:
            raise exceptions.AuthenticationFailed(
                'Authentication credentials were not provided.')

        try:
            payload = jwt.decode(
                refresh_token, settings.REFRESH_TOKEN_SECRET, algorithms=['HS256'])

        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed(
                'session expired please log in again')

        user = User.objects.filter(id=payload.get('user_id')).first()

        if user is None:
            raise exceptions.AuthenticationFailed('User not found')

        if not user.is_active:
            raise exceptions.AuthenticationFailed('user is inactive')

        access_token = generate_access_token(user)

        return Response({'access_token': access_token})
