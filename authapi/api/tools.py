"""
Helper function
"""

import hashlib
import secrets
import string

from ..settings import get_settings


def blake2b_hash(input_string: str):
    """
    Function to hash a string using the blake2b algorithm
    """
    input_bytes = input_string.encode("utf-8")
    hash_object = hashlib.blake2b(digest_size=64, salt=get_settings().salt.encode())
    hash_object.update(input_bytes)
    hashed_string = hash_object.hexdigest()

    return hashed_string


def generate_random_password(length: int = 32):
    """
    generate a varying character string
    Includes:
    1. Letters (upper and lowercase ),
    2. Numbers
    3. Characters - and _
    """
    chars = string.digits + string.ascii_lowercase + string.ascii_uppercase
    chars2 = string.digits + string.ascii_lowercase + string.ascii_uppercase + "_-"
    return secrets.choice(chars) + "".join(
        secrets.choice(chars2) for i in range(length - 1)
    )
