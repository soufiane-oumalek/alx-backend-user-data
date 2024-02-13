#!/usr/bin/env python3
"""Authentication module for the API.
"""
import re
from typing import List, TypeVar
from flask import request


class Auth:
    """Authentication class.
    """
    def require_auth(path: str, excluded_paths: List[str]) -> bool:
        """Checks if authentication is required for a given path."""
        if path is None or excluded_paths is None or not len(excluded_paths):
            return True

        path = path if path.endswith('/') else path + '/'

        for excluded_path in excluded_paths:
            if excluded_path.endswith('*'):
                if path.startswith(excluded_path[:-1]):
                    return False
            elif path == excluded_path or path.startswith(excluded_path + '/'):
                return False

        return True


    def authorization_header(self, request=None) -> str:
        """Gets the authorization header field from the request.
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Gets the current user from the request.
        """
        return None
