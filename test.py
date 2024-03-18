"""Test requests"""

import argparse
import os
from pprint import pprint

import requests
from dotenv import load_dotenv

load_dotenv()

SERVER_URL = "http://localhost:8000"


def get_headers():
    """Get token header"""
    token = get_token()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    return headers


def get_token():
    """Get user token"""
    resp = requests.post(
        f"{SERVER_URL}/login",
        json={
            "username": "admin",
            "password": os.environ["ADMIN_PASSWORD"],
            "scopes": ["admin"],
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
    parser = argparse.ArgumentParser(description="entrypoint options.")

    # Add arguments and options to the parser
    parser.add_argument(
        "entrypoint",
        help="which entrypoint to use.",
        choices=["get-token", "add-client", "get-client", "get-clients"],
    )
    args = parser.parse_args()

    if args.entrypoint == "get-token":
        pprint(get_token())
    elif args.entrypoint == "add-client":
        pprint(create_client())
    elif args.entrypoint == "get-client":
        client_id = input("enter client id:")
        pprint(get_client(client_id))
    elif args.entrypoint == "get-clients":
        pprint(get_clients())
