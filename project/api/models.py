# project/api/models.py

from flask import current_app as app

from datetime import datetime

from project import db
from project.api.crypto import verify_hash, create_hash


class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(128), unique=True, nullable=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    pw_hash = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean, default=False, nullable=False)
    disabled = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    last_access = db.Column(db.DateTime, nullable=True)
    invited_by = db.Column(db.Integer, nullable=True)
    cbl_member = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self,
                 username,
                 email,
                 id=None,
                 password=None,
                 active=False,
                 disabled=False,
                 created_at=datetime.utcnow(),
                 last_login=None,
                 last_access=None,
                 invited_by=None,
                 cbl_member=False):

        if not (id or password or invited_by):
            raise ValueError('id, password or invited_by must be set')

        if id:
            self.id = id

        self.username = username
        self.email = email
        self.active = active
        self.disabled = disabled
        self.created_at = created_at
        self.last_login = last_login
        self.last_access = last_access
        self.invited_by = invited_by
        self.cbl_member = cbl_member

        if password:
            self.set_password(password)
        else:
            active = False

    def check_password(self, password):
        return verify_hash(password, self.pw_hash)

    def set_password(self, password):

        min_length = app.config['PASSWORD_MIN_LEN']
        if len(password) < min_length:
            raise ValueError('password must be at least {} characters'.format(min_length))

        self.pw_hash = create_hash(password)
