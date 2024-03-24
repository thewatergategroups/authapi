"""
Important Application wide schemas for JWT authentication 
"""

import base64
from enum import StrEnum
from functools import lru_cache
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import BaseModel
from sqlalchemy import insert, select
from sqlalchemy.orm import Session
from yumi import Algorithms

from .database.models import CertModel
from .deps import get_sync_sessionm


class Jwk(BaseModel):
    """Base model for JWK's that adds extra useful functionality used by child classes"""

    kty: str
    kid: str
    use: str

    @staticmethod
    def encode(value: int):
        """return a base64 encoded equivalent of a passed in integer"""
        encoded_bytes = value.to_bytes(
            length=(value.bit_length() + 7) // 8, byteorder="big"
        )
        return base64.urlsafe_b64encode(encoded_bytes).rstrip(b"=").decode("ascii")

    @classmethod
    def get(cls, _: Any):
        """return an instance of self"""
        return cls(kty="JWT", kid="123", use="none")

    @staticmethod
    def generate_pk():
        """Placeholder function to be implemented by child objects"""
        raise NotImplementedError("Not yet implemented for this class")


class EcJwk(Jwk):
    """Eliptical Curve JWK Algorithm implementation"""

    crv: str
    x: bytes
    y: bytes

    @classmethod
    @lru_cache
    def get(cls, public_numbers: ec.EllipticCurvePublicNumbers):
        return cls(
            kty="EC",
            kid=Alg.EC.value,
            use="sig",
            alg=Alg.EC.value,
            crv="P-256",
            x=cls.encode(public_numbers.x),
            y=cls.encode(public_numbers.y),
        )

    @staticmethod
    def generate_pk():
        """Generate a private key usinng the eliptical curve algorithm"""
        return ec.generate_private_key(ec.SECP256R1(), default_backend())


class RsaJwk(Jwk):
    """RSA JWK Algorithm implementation"""

    n: bytes
    e: bytes

    @classmethod
    @lru_cache
    def get(cls, public_numbers: rsa.RSAPublicNumbers):
        return cls(
            kty="RSA",
            kid=Alg.RSA.value,
            use="sig",
            alg=Alg.RSA.value,
            n=cls.encode(public_numbers.n),
            e=cls.encode(public_numbers.e),
        )

    @staticmethod
    def generate_pk():
        """Generate a private key usinng the RSA algorithm"""
        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )


class Alg(StrEnum):
    """
    1. Enum defining allowed algorithms
    2. some helper functions to make the algorithms accessible
    """

    def __init__(self, algorithm: str):
        super().__init__()
        self.alg = algorithm
        maps = {Algorithms.EC.value: EcJwk, Algorithms.RSA.value: RsaJwk}
        self.model: Jwk = maps.get(self.value, Jwk)

    EC = Algorithms.EC.value
    RSA = Algorithms.RSA.value

    @classmethod
    @lru_cache
    def get_public_keys(cls):
        """return all public keys for all algorithms"""
        return [item.load_public_key() for item in cls]

    @lru_cache
    def load_private_key(self):
        """load private key for a particular algorithm from the database"""
        with get_sync_sessionm().begin() as session:  # pylint: disable=no-member
            cert = session.scalar(select(CertModel).where(CertModel.alg == self.alg))
            if not cert:
                raise ValueError(f"missing certificate for algorithm {self.alg}")
            return serialization.load_pem_private_key(
                cert.cert, password=None, backend=default_backend()
            )

    @lru_cache
    def load_public_key(self):
        """return the public key for a particular algorithm"""
        private_key = self.load_private_key()
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        return self.model.get(public_numbers).model_dump()

    def generate_private_key(self):
        """Generate a private key for a particular algorithm"""
        private_key = self.model.generate_pk()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return private_pem

    def insert_cert(self, session: Session, private_pem: bytes):
        """insert a private key into the database"""
        session.execute(insert(CertModel).values(alg=self.value, cert=private_pem))
