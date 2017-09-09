# project/api/auth.py

from flask import Blueprint, jsonify, request
from flask import current_app as app

from project.api.utils import requires_post_data
from project.api.crypto import encode_url_token, decode_url_token
from project.api.email import send_password_reset, send_invite
from project.api.users import get_by_email, get_active_by_email, try_log_in, \
    register_invite, update_user

from project.api.jwt import authenticated, \
    authenticated_fresh_cbl, authenticated_refresh, \
    current_user, set_login_jwt, set_refresh_jwt, logout_jwt

auth_blueprint = Blueprint('auth', __name__, url_prefix='/auth')


@auth_blueprint.route('/login', methods=['POST'])
@requires_post_data
def login():

    data = request.get_json()
    email = data.get('email', None)
    password = data.get('password', None)

    try:
        if email and password:

            user = try_log_in(email, password)

            if user:
                resp = jsonify({'login': True})
                set_login_jwt(user, resp)
                return resp, 200

        return jsonify({'login': False}), 401

    except Exception as e:
        print(e)
        return jsonify({'login': False}), 401


@auth_blueprint.route('/refresh', methods=['POST'])
@authenticated_refresh
def refresh():
    # Create the new access token
    resp = jsonify({'refresh': True})
    set_refresh_jwt(current_user, resp)
    return resp, 200


@auth_blueprint.route('/logout', methods=['POST'])
@authenticated
def logout():

    resp = jsonify({'logout': True})
    logout_jwt(request, resp)
    return resp, 200


@auth_blueprint.route('/createinvite', methods=['POST'])
@requires_post_data
@authenticated_fresh_cbl
def create_invite():

    data = request.get_json()
    email = data.get('email', None)
    name = data.get('name', None)
    message = data.get('message', None)
    suppress_email = data.get('suppress_email', None)

    if not email or not name:
        return jsonify({'msg': 'Invalid Data'}), 400

    token = encode_url_token('invite', email)

    active, disabled = register_invite(invited_by=current_user.id,
                                       email=email
                                       )
    if disabled:
        return jsonify({'msg': 'User banned!'}), 403
    if active:
        return jsonify({'msg': 'User already exists'}), 409

    if not suppress_email:
        send_invite(invited_by_username=current_user.username,
                    invited_by_email=current_user.email,
                    email=email,
                    name=name,
                    message=message if message else '',
                    token=token)

    return jsonify({'msg': 'Invite sent'}), 200


@auth_blueprint.route('/activate', methods=['GET', 'POST'])
@requires_post_data
def activate():

    token = request.args.get('id')

    if not token:
        return jsonify({'msg': 'Invalid Data'}), 400

    expired, invalid, action, email = decode_url_token(token)

    if expired:
        return jsonify({'msg': 'token expired'}), 400
    elif invalid:
        return jsonify({'msg': 'token invalid'}), 400
    elif action != 'invite':
        return jsonify({'msg': 'action mismatch'}), 400

    user = get_by_email(email)

    if not user:
        return jsonify({'msg': 'email mismatch'}), 400

    if user.active:
        return jsonify({'msg': 'account already active'}), 400

    if user.disabled:
        return jsonify({'msg': 'account disabled'}), 400

    if request.method == 'GET':
        return jsonify({'token': token}), 200

    data = request.get_json()
    post_email = data.get('email', None)
    username = data.get('username', None)
    password = data.get('password', None)

    if post_email != email:
        return jsonify({'msg': 'email mismatch'}), 400

    try:
        update_user(user, username=username, password=password, active=True)
        return jsonify({'msg': 'Account activated'}), 200
    except ValueError as e:
        return jsonify({'msg': str(e)}), 400


@auth_blueprint.route('/changepassword', methods=['POST'])
@authenticated
@requires_post_data
def change_password():

    logout_jwt(request, jsonify({'msg': 'edd'}))

    data = request.get_json()
    old_password = data.get('old_password', None)
    new_password = data.get('new_password', None)

    user = try_log_in(current_user.email, old_password)

    if not user:
        return jsonify({'msg': 'Incorrect password'}), 401

    try:
        update_user(user, password=new_password)
        return jsonify({'msg': 'Password changed successfully'}), 200
    except ValueError as e:
        return jsonify({'msg': str(e)}), 400


@auth_blueprint.route('/forgotpassword', methods=['POST'])
@requires_post_data
def forgot_password():

    data = request.get_json()
    email = data.get('email', None)

    if not email:
        return jsonify({'msg': 'Invalid Data'}), 400

    user = get_active_by_email(email)

    if user:

        token = encode_url_token('password', email)
        send_password_reset(email, user.username, token)

    return jsonify({'msg': 'If it was recognised, an email was sent to the address provided'}), 200


@auth_blueprint.route('/resetpassword', methods=['GET', 'POST'])
@requires_post_data
def reset_password():

    token = request.args.get('id')

    if not token:
        return jsonify({'msg': 'Invalid Data'}), 400

    expired, invalid, action, email = decode_url_token(token)

    if expired:
        return jsonify({'msg': 'token expired'}), 400
    elif invalid:
        return jsonify({'msg': 'token invalid'}), 400
    elif action != 'password':
        return jsonify({'msg': 'action mismatch'}), 400

    user = get_active_by_email(email)

    if not user:
        return jsonify({'msg': 'email mismatch'}), 400

    if request.method == 'GET':
        return jsonify({'token': token}), 200

    data = request.get_json()
    post_email = data.get('email', None)
    password = data.get('password', None)

    if post_email != email:
        return jsonify({'msg': 'email mismatch'}), 400

    try:
        update_user(user, password=password)
        return jsonify({'msg': 'Password changed successfully'}), 200
    except ValueError as e:
        return jsonify({'msg': str(e)}), 400
