
import redis
from flask import jsonify
from flask import current_app as app

from project import jwt
from project.api.models import User
from project.api.users import get_active_by_id

from flask_jwt_extended import jwt_required, fresh_jwt_required, \
    jwt_refresh_token_required, \
    create_access_token, create_refresh_token, \
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies, \
    get_jti, get_jwt_claims, current_user

from functools import wraps


revoked_store = redis.StrictRedis(host='cbl-redis', port=6379, db=0,
                                  decode_responses=True)


def authenticated(f):
    @jwt_required
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated_function


def authenticated_cbl(f):
    @jwt_required
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.cbl_member:
            return jsonify({'msg': 'Core CBL members only'}), 403

        return f(*args, **kwargs)
    return decorated_function


def authenticated_fresh(f):
    @fresh_jwt_required
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated_function


def authenticated_fresh_cbl(f):
    @fresh_jwt_required
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.cbl_member:
            return jsonify({'msg': 'Core CBL members only'}), 403

        return f(*args, **kwargs)
    return decorated_function


def authenticated_refresh(f):
    @jwt_refresh_token_required
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated_function


@jwt.user_claims_loader
def add_claims_to_access_token(user):
    return {"id": user.id,
            "email": user.email,
            "username": user.username,
            "cbl_member": user.cbl_member
            }


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


@jwt.user_loader_callback_loader
def user_loader_callback(identity):

    claims = get_jwt_claims()

    if claims == {}:  # refresh token used, read from db
        tmpUser = get_active_by_id(identity)

        if tmpUser:
            return User(
                id=tmpUser.id,
                email=tmpUser.email,
                username=tmpUser.username,
                cbl_member=tmpUser.cbl_member
            )

    return User(
        id=claims['id'],
        email=claims['email'],
        username=claims['username'],
        cbl_member=claims['cbl_member']
    )


@jwt.token_in_blacklist_loader
def check_if_token_is_revoked(decrypted_token):
    jti = decrypted_token['jti']
    entry = revoked_store.get(jti)
    if entry is None:
        return True
    return entry == 'true'


def set_login_jwt(user, resp):

    # generate tokens
    access_token = create_access_token(identity=user, fresh=True)
    refresh_token = create_refresh_token(identity=user)

    # set redis entry
    revoked_store.set(
        get_jti(access_token),
        'false',
        blacklist_access_token_expires())
    revoked_store.set(
        get_jti(refresh_token),
        'false',
        blacklist_refresh_token_expires())

    # add cookies
    set_access_cookies(resp, access_token)
    set_refresh_cookies(resp, refresh_token)


def set_refresh_jwt(user, resp):

    # generate token
    access_token = create_access_token(identity=user, fresh=False)

    revoked_store.set(
        get_jti(access_token),
        'false',
        blacklist_access_token_expires())

    set_access_cookies(resp, access_token)


def revoke_jwt(encoded_token, expires):

    jti = get_jti(encoded_token)
    revoked_store.set(jti, 'true', expires)


def logout_jwt(request, resp):

    access_cookie_name = app.config['JWT_ACCESS_COOKIE_NAME']
    access_token = request.cookies.get(access_cookie_name)
    revoke_jwt(access_token, blacklist_access_token_expires())

    refresh_cookie_name = app.config['JWT_REFRESH_COOKIE_NAME']
    refresh_token = request.cookies.get(refresh_cookie_name)
    revoke_jwt(refresh_token, blacklist_refresh_token_expires())

    unset_jwt_cookies(resp)


def blacklist_access_token_expires():
    return app.config['JWT_ACCESS_TOKEN_EXPIRES'] * 1.2


def blacklist_refresh_token_expires():
    return app.config['JWT_REFRESH_TOKEN_EXPIRES'] * 1.2
