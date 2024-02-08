#!/usr/bin/env python3
"""
Encrypting passwords
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """ Returns a salted, hashed password, which is a byte string """
    encod= password.encode()
    hash = bcrypt.hashpw(encod, bcrypt.gensalt())

    return hash


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Validates the provided password matches the hashed password """
    valid = False
    encod = password.encode()
    if bcrypt.checkpw(encod, hashed_password):
        valid = True
    return valid
