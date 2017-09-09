# project/api/utils.py

from functools import wraps

from flask import request, jsonify


def requires_post_data(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST' and not request.is_json:
            response_object = {
                'msg': 'Invalid payload.'
            }
            return jsonify(response_object), 400

        return f(*args, **kwargs)
    return decorated_function


