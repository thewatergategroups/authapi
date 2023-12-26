import base64
from functools import lru_cache
from pydantic import BaseModel
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from .settings import get_settings
from enum import StrEnum


class Jwt(BaseModel):
    aud: str
    sub: str
    scopes: list[str]
    exp: int
    # iat:str
    # iss:str
    # jti:str


class Jwk(BaseModel):
    kty: str
    kid: str
    use: str

    @staticmethod
    def encode(value: int):
        return base64.b64encode(value.to_bytes(length=(value.bit_length() + 7) // 8))

    @classmethod
    def get(cls, *args, **kwargs):
        raise NotImplementedError("Not yet implemented for this class")

    @staticmethod
    def generate_pk():
        raise NotImplementedError("Not yet implemented for this class")


class EcJwk(Jwk):
    crv: str
    x: bytes
    y: bytes

    @classmethod
    @lru_cache
    def get(cls, public_numbers: ec.EllipticCurvePublicNumbers):
        return cls(
            kty="EC",
            kid=str(uuid4()),
            use="sig",
            alg=Alg.EC.value,
            crv="P-256",
            x=cls.encode(public_numbers.x),
            y=cls.encode(public_numbers.y),
        )

    @staticmethod
    def generate_pk():
        return ec.generate_private_key(ec.SECP256R1(), default_backend())


class RsaJwk(Jwk):
    n: bytes
    e: bytes

    @classmethod
    @lru_cache
    def get(cls, public_numbers: rsa.RSAPublicNumbers):
        return cls(
            kty="RSA",
            kid=str(uuid4()),
            use="sig",
            alg=Alg.RSA.value,
            n=cls.encode(public_numbers.n),
            e=cls.encode(public_numbers.e),
        )

    @staticmethod
    def generate_pk():
        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )


class Alg(StrEnum):
    def __init__(self, algorithm: str):
        super().__init__()
        self.alg = algorithm
        maps = {"ES256": EcJwk, "RS256": RsaJwk}
        self.model = maps.get(self.value, Jwk)

    EC = "ES256"
    RSA = "RS256"

    @classmethod
    @lru_cache
    def get_public_keys(cls):
        return [item.load_public_key() for item in cls]

    @lru_cache
    def load_private_key(self):
        with open(f"{get_settings().certs_folder}/{self.value}.pem", "rb") as f:
            private_pem = f.read()

        private_key = serialization.load_pem_private_key(
            private_pem, password=None, backend=default_backend()
        )

        return private_key

    @lru_cache
    def load_public_key(self):
        private_key = self.load_private_key()
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        return self.model.get(public_numbers).dict()

    def generate_and_save_private_key(self):
        private_key = self.model.generate_pk()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(f"{get_settings().certs_folder}/{self.value}.pem", "wb") as f:
            f.write(private_pem)
