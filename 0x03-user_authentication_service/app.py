#!/usr/bin/env python3
""" Basic Flask app, Register user, Log in, Log out, User profile,
    Get reset passwords token, Update password end-point """
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth
app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'], strict_slashes=False)
def welcome():
    """ Basic Flask that return message """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users():
    """ Register user """
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"}), 200
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login():
    """ Log in
    return response"""
    email = request.form.get('email')
    password = request.form.get('password')
    if AUTH.valid_login(email, password) is False:
        abort(401)
    session_id = AUTH.create_session(email)
    res = jsonify({'email': email, 'message': 'logged in'})
    res.set_cookie('session_id', session_id)
    return res


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout():
    """ Log out
    return message"""
    session_id = request.cookies.get('session_id')
    logout_user = AUTH.get_user_from_session_id(session_id)
    if session_id is None or logout_user is None:
        abort(403)
    AUTH.destroy_session(logout_user.id)
    return redirect('/')


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile():
    """ User profile
    return email"""
    session_id = request.cookies.get('session_id')
    prof_user = AUTH.get_user_from_session_id(session_id)
    if session_id is None or prof_user is None:
        abort(403)
    return jsonify({"email": prof_user.email}), 200


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token():
    """ generate password token """
    try:
        email_usr = request.form.get('email')
        token_usr = AUTH.get_reset_password_token(email_usr)
        return jsonify({"email": email_usr, "reset_token": token_usr}), 200
    except ValueError:
        abort(403)


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password():
    """ Update password """
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    password = request.form.get('new_password')
    try:
        AUTH.update_password(reset_token, password)
    except Exception:
        abort(403)
    return jsonify({"email": email, "message": "Password updated"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
