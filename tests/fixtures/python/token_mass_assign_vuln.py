"""
Fixture for token_mass_assign_guard.py (v1.38.0). Mirrors DownUnderCTF
2023's real "grades-grades-grades" signup route: the whole submitted form
becomes the JWT payload, so a client-added is_teacher field is signed.
"""
import jwt
from flask import request, current_app


def signup():
    jwt_data = request.form.to_dict()
    jwt_cookie = current_app.auth.create_token(jwt_data)  # ruleid: Mass Assignment
    return jwt_cookie


def api_login():
    return jwt.encode(request.get_json(), "k", algorithm="HS256")  # ruleid: Mass Assignment
