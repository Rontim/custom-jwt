import datetime
import jwt
import uuid
from django.conf import settings


def generate_access_token(user):
    payload = {
        'user_id': user.id,
        'username': user.username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=60),
        'iat': datetime.datetime.utcnow(),
    }

    access = jwt.encode(payload, key=settings.SECRET_KEY, algorithm='HS256')

    return access


def generate_refresh_token(user):
    payload = {
        'user_id': user.id,
        'uuid': str(uuid.uuid4()),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow()
    }
    refresh = jwt.encode(
        payload, key=settings.REFRESH_TOKEN_SECRET, algorithm='HS256')

    return refresh
