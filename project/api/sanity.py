# project/api/users.py

from flask import Blueprint, jsonify

from project.api.jwt import authenticated, current_user



from flask_jwt_extended import jwt_required

sanity_blueprint = Blueprint('sanity', __name__, url_prefix='/sanity')

@sanity_blueprint.route('/ping', methods=['GET'])
def ping_pong():
    return jsonify({
        'status': 'success',
        'message': 'pong!'
    })

@sanity_blueprint.route('/protected', methods=['POST', 'GET'])
# @authenticated
@jwt_required
def protected():
    return jsonify({'msg': 'success'}), 200


@sanity_blueprint.route('/unprotected', methods=['POST', 'GET'])
def unprotected():
    return jsonify({'msg': 'success'}), 200


@sanity_blueprint.route('/claim', methods=['POST', 'GET'])
@authenticated
def claim():
    return jsonify({"email": current_user.email,
                    "cbl_member": current_user.cbl_member,
                    "username": current_user.username
                    }), 200