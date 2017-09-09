# project/api/managers/user_manager.py

# import project.api.models.user
from project.api.models import User
from project import db
from sqlalchemy import exc

def get_active_by_id(id):

    user = User.query.get(id)

    if user and user.active and not user.disabled:
        return user


def get_by_email(email):

    return User.query.filter_by(email=email).first()


def get_active_by_email(email):

    user = User.query.filter_by(email=email).first()

    if user and user.active and not user.disabled:
        return user


def try_log_in(email, password):

    user = get_active_by_email(email)

    if user and user.check_password(password):
        return user


def register_invite(invited_by, email):

    user = User.query.filter_by(email=email).first()
    active, disabled = False, False

    if user:
        active = user.active
        disabled = user.disabled

    if not active and not disabled:
        if not user:
            user = User(username=email,
                        email=email,
                        invited_by=invited_by
                        )
            user.pw_hash = "NOT SET"
            db.session.add(user)
        else:
            user.invited_by = invited_by

        db.session.commit()

    return active, disabled


def update_user(user, username=None, password=None, active=None, disabled=None):

    if username:
        user.username = username

    if password:
        user.set_password(password)

    if active:
        user.active = active

    if disabled:
        user.disabled = disabled

    try:
        db.session.commit()
    except (exc.IntegrityError):
        db.session.rollback()
        raise ValueError('Username already in use')

    return user
