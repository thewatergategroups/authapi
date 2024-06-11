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
    token = get_token()["token"]
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


def create_client():
    """Request to create a client"""
    resp = requests.post(
        f"{SERVER_URL}/clients/create",
        headers=get_headers(),
        json={
            "name": "ciaran",
            "type": "confidential",
            "description": "ciarans test client",
            "redirect_uris": [f"{SERVER_URL}/users/user"],
            "grant_types": ["authorization_code"],
            "scopes": ["admin"],
        },
        timeout=2,
    )
    return resp.json()


def get_client(cl_id: str):
    """get an existing client"""
    resp = requests.get(
        f"{SERVER_URL}/clients/client",
        params={"client_id": cl_id},
        headers=get_headers(),
        timeout=2,
    )
    return resp.json()


def get_clients():
    """get all clients"""
    resp = requests.get(f"{SERVER_URL}/clients", headers=get_headers(), timeout=2)
    return resp.json()


if __name__ == "__main__":

    pprint(get_token())
