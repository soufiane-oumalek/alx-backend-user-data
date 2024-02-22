#!/usr/bin/env python3
""" Hash password """
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from db import DB
from user import User


def _hash_password(password: str) -> str:
    """  hash password.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


class Auth:
    """Auth class.
    """

    def __init__(self):
        """ init """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ register user """
        try:
            regter_user = self._db.find_user_by(email=email)
        except NoResultFound:
            pwd = _hash_password(password)
            regter_user = self._db.add_user(email, pwd)
            return regter_user
        else:
            raise ValueError('User {email} already exists')

    def valid_login(self, email: str, password: str) -> bool:
        """ validation login """
        try:
            v_user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        else:
            return bcrypt.checkpw(password=password.encode('utf-8'),
                                  hashed_password=v_user.hashed_password)

    def create_session(self, email: str) -> str:
        """ creat session """
        try:
            sess_user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        else:
            session_id = _generate_uuid()
            self._db.update_user(sess_user.id, session_id=session_id)
            return session_id

    def get_user_from_session_id(self, session_id: str) -> str:
        """ get user from session id """
        try:
            get_user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        else:
            return get_user

    def destroy_session(self, user_id: int) -> None:
        """ destroy session """
        try:
            self._db.update_user(user_id, session_id=None)
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """ reset password """
        try:
            res_user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        token = _generate_uuid()
        self._db.update_user(res_user.id, reset_token=token)
        return token

    def update_password(self, reset_token: str, password: str) -> None:
        """ update password """
        try:
            up_user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        pwd = _hash_password(password)
        self._db.update_user(up_user.id, hashed_password=pwd, reset_token=None)


def _generate_uuid() -> str:
    """ Generate uuid
    """
    return str(uuid.uuid4())
