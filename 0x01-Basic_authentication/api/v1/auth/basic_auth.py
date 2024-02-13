#!/usr/bin/env python3
"""Basic authentication module for the API.
"""
import re
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """Class basic authentication.
    """
    def extract_base64_authorization_header(
            self,
            authorization_header: str) -> str:
        """Extracts the Base64 for a Basic Authentication.
        """
        if type(authorization_header) == str:
            patt = r'Basic (?P<token>.+)'
            f_match = re.fullmatch(patt, authorization_header.strip())
            if f_match is not None:
                return f_match.group('token')
        return None

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str,
            ) -> str:
        """Decodes base64-encoded authorization.
        """
        if type(base64_authorization_header) == str:
            try:
                result = base64.b64decode(
                    base64_authorization_header,
                    validate=True,
                )
                return result.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str,
            ) -> Tuple[str, str]:
        """Extracts user credentials from a base64-decoded authorization.
        """
        if type(decoded_base64_authorization_header) == str:
            patt = r'(?P<user>[^:]+):(?P<password>.+)'
            f_match = re.fullmatch(
                patt,
                decoded_base64_authorization_header.strip(),
            )
            if f_match is not None:
                user = f_match.group('user')
                passwrd = f_match.group('password')
                return user, passwrd
        return None, None

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """Retrieves a user.
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieves the user from a request.
        """
        authoriz_header = self.authorization_header(request)
        b_auth_tkn = self.extract_base64_authorization_header(authoriz_header)
        authoriz_tkn = self.decode_base64_authorization_header(b_auth_tkn)
        email, password = self.extract_user_credentials(authoriz_tkn)
        return self.user_object_from_credentials(email, password)
