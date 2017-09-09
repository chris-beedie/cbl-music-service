# project/api/email.py

import requests

from flask import render_template
from datetime import datetime
from flask import current_app as app


def send_mail(subject, email, template, context):
    """Send an email via mailgun.
    :param subject: Email subject
    :param email: Email recipient
    :param template: The name of the email template
    :param context: The context to render the template with
    """
    key = app.config['MAILGUN_KEY']
    url = app.config['MAILGUN_URL']
    email_from = app.config['MAILGUN_FROM']
    html = render_template('%s.html' % template, **context)

    return requests.post(
        url,
        auth=("api", key),
        data={"from": email_from,
              "to": email,
              "subject": subject,
              "html": html})


def send_password_reset(email, username, token):

    base_url = app.config['BASE_URL']
    action_url = '{}/resetpassword?id={}'.format(base_url, token)

    context = {'username': username,
               'year': datetime.now().year,
               'base_url': base_url,
               'action_url': action_url}
    return send_mail('CBL - Reset Password', email, 'reset_password', context)


def send_invite(invited_by_username, invited_by_email, email, name, message, token):

    base_url = app.config['BASE_URL']
    action_url = '{}/invite?id={}'.format(base_url, token)

    context = {'invited_by_username': invited_by_username,
               'invited_by_email': invited_by_email,
               'name': name,
               'message': message,
               'year': datetime.now().year,
               'base_url': base_url,
               'action_url': action_url}
    return send_mail('CBL - You\'re Invited!', email, 'invite', context)