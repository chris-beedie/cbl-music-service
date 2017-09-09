# project/tests/utils.py


import datetime
import json

from project import db
from project.api.models import User


def add_user(username, email, password, active=True, disabled=False, cbl_member=False):
    user = User(
        username=username,
        email=email,
        password=password,
        cbl_member=cbl_member,
        active=active,
        disabled=disabled)
    db.session.add(user)
    db.session.commit()
    return user


def login_user(client, email, password, refresh_only=False):
    resp = client.post(
        '/auth/login',
        data=json.dumps(dict(
            email=email,
            password=password
        )),
        content_type='application/json'
    )

    access_cookie_value, access_csrf, refresh_csrf = None, None, None

    if not refresh_only:
        access_cookie_str = resp.headers[1][1]
        access_cookie_key = access_cookie_str.split('=')[0]
        access_cookie_value = "".join(access_cookie_str.split('=')[1:]).split(';')[0]
        client.set_cookie('localhost', access_cookie_key, access_cookie_value)

        access_csrf_str = resp.headers[2][1]
        access_csrf_key = access_csrf_str.split('=')[0]
        access_csrf_value = "".join(access_csrf_str.split('=')[1:])
        client.set_cookie('localhost', access_csrf_key, access_csrf_value)
        access_csrf = access_csrf_value.split(';')[0]

    refresh_cookie_str = resp.headers[3][1]
    refresh_cookie_key = refresh_cookie_str.split('=')[0]
    refresh_cookie_value = "".join(refresh_cookie_str.split('=')[1:]).split(';')[0]
    client.set_cookie('localhost', refresh_cookie_key, refresh_cookie_value)

    refresh_csrf_str = resp.headers[4][1]
    refresh_csrf_key = refresh_csrf_str.split('=')[0]
    refresh_csrf_value = "".join(refresh_csrf_str.split('=')[1:])
    client.set_cookie('localhost', refresh_csrf_key, refresh_csrf_value)
    refresh_csrf = refresh_csrf_value.split(';')[0]

    return access_csrf, refresh_csrf, access_cookie_value
