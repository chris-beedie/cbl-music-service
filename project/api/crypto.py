from project import bcrypt
from datetime import timedelta
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import current_app as app


def verify_hash(data, hash):
    return bcrypt.check_password_hash(hash, data)


def create_hash(data):
    return bcrypt.generate_password_hash(data).decode('utf-8')


def serialiser(secret_key, salt):
    return URLSafeTimedSerializer(secret_key=secret_key, salt=salt)


def encode_url_token(action, email):
    secret_key = app.config.get('SECRET_KEY')
    salt = app.config.get('SALT')
    email_hash = create_hash(email)
    return serialiser(secret_key, salt).dumps([action, email, email_hash])


def decode_url_token(token):

    secret_key = app.config.get('SECRET_KEY')
    salt = app.config.get('SALT')

    max_age = timedelta(days=1).seconds
    expired, invalid = False, False
    action, email = None, None
    serial = serialiser(secret_key, salt)

    try:
        data = serial.loads(token, max_age=max_age)

        action = data[0]
        email = data[1]

        invalid = not verify_hash(data[1], data[2])

    except SignatureExpired:
        expired = True
    except (BadSignature, TypeError, ValueError):
        invalid = True

    return expired, invalid, action, email

