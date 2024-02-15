#!/usr/bin/env python3
"""
Authentication class
"""

from tabnanny import check
from flask import request
from typing import TypeVar, List
User = TypeVar('User')


class Auth:
    """
    class API authentication
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        authentication method
        """
        check = path
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != "/":
            check += "/"
        if check in excluded_paths or path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        authorization method
        """
        if request is None:
            return None
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> User:
        """
        current method
        """
        return None

    def session_cookie(self, request=None):
        """ returns a request cookie  """
        if request is None:
            return None
        session = getenv('SESSION_NAME')
        return request.cookies.get(session)
