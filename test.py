"""Test requests"""

import argparse
import os
from pprint import pprint

import requests
from dotenv import load_dotenv

load_dotenv()

SERVER_URL = "https://auth.thewatergategroups.com"


def get_headers():
    """Get token header"""
    token = get_token()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    return headers


def get_token():
    """Get user token"""
    resp = requests.post(
        f"{SERVER_URL}/login",
        data={
            "email": "admin@email.com",
            "password": os.environ["ADMIN_PASSWORD"],
            "alg": "ES256",
        },
        timeout=2,
    )
    return resp.json()


def get_params():
    resp = requests.get(
        "https://resource.thewatergategroups.com/parameters",
        headers=get_headers(),
        timeout=2,
    )
    return resp.json()


if __name__ == "__main__":

    pprint(get_params())
