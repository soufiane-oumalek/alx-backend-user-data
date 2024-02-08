#!/usr/bin/env python3
"""
Check valid password
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """ that expects one string argument name password and returns a salted,
    hashed password, which is a byte string. """
    encde = password.encode()
    hash = bcrypt.hashpw(encde, bcrypt.gensalt())
    return hash


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ function that expects 2 arguments and returns a boolean."""
    valid = False
    encde = password.encode()
    if bcrypt.checkpw(encde, hashed_password):
        valid = True
    return valid
