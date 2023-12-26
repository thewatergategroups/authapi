from functools import lru_cache
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from .settings import get_settings
from enum import StrEnum
from uuid import uuid4
import base64


@lru_cache
def get_ec_jwk(public_numbers: ec.EllipticCurvePublicNumbers):
    return {
        "kty": "EC",
        "kid": str(uuid4()),
        "use": "sig",
        "alg": "ES256",
        "crv": "P-256",
        "x": base64.b64encode(
            public_numbers.x.to_bytes(length=(public_numbers.x.bit_length() + 7) // 8)
        ),
        "y": base64.b64encode(
            public_numbers.y.to_bytes(length=(public_numbers.y.bit_length() + 7) // 8)
        ),
    }


@lru_cache
def get_rsa_jwk(public_numbers: rsa.RSAPublicNumbers):
    return {
        "kty": "RSA",
        "kid": str(uuid4()),
        "use": "sig",
        "alg": "RS256",
        "n": base64.b64encode(str(public_numbers.n).encode()),
        "e": base64.b64encode(str(public_numbers.e).encode()),
    }


class Alg(StrEnum):
    EC = "ES256"
    RSA = "RS256"

    @classmethod
    @lru_cache
    def get_public_keys(cls):
        return [load_public_key(item) for item in cls]


ALG_JWK_MAPPING = {Alg.EC: get_ec_jwk, Alg.RSA: get_rsa_jwk}


def generate_and_save_private_key(alg: Alg):
    if alg == Alg.EC:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    elif alg == Alg.RSA:
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
    else:
        raise ValueError(f"{alg} is not a valid option")
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open(f"{get_settings().certs_folder}/{alg.value}.pem", "wb") as f:
        f.write(private_pem)


@lru_cache
def load_private_key(alg: Alg):
    with open(f"{get_settings().certs_folder}/{alg.value}.pem", "rb") as f:
        private_pem = f.read()

    private_key = serialization.load_pem_private_key(
        private_pem, password=None, backend=default_backend()
    )

    return private_key


@lru_cache
def load_public_key(alg: Alg):
    # Load private key from a file
    private_key = load_private_key(alg)
    # Extract public key information
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    return ALG_JWK_MAPPING[alg](public_numbers)
