#!/usr/bin/env python3
""" handles all routes for the views for Session authentication """
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User
from os import getenv


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> str:
    """ view for route /auth_session/login, method POST """
    email = request.form.get('email')
    if not email:
        return jsonify({"error": "email missing"}), 400
    password = request.form.get('password')
    if not password:
        return jsonify({"error": "password missing"}), 400
    user = User.search({'email': email})
    if not user:
        return jsonify({"error": "no user found for this email"}), 404
    for u in user:
        if u.is_valid_password(password):
            from api.v1.app import auth
            session_id = auth.create_session(u.id)
            user_res = jsonify(u.to_json())
            user_res.set_cookie(getenv('SESSION_NAME'), session_id)
            return user_res
        else:
            return jsonify({"error": "wrong password"}), 401


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout() -> str:
    """ view for route /auth_session/logout, method DELETE """
    from api.v1.app import auth
    destroy_session = auth.destroy_session(request)
    if destroy_session is False:
        abort(404)
    else:
        return jsonify({}), 200
