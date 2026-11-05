"""
Safe counterparts to token_mass_assign_vuln.py: the token payload is
built from individually chosen fields, and a whole-request dict that is
only stored (never minted into a token) doesn't count.
"""
import jwt
from flask import request


def signup():
    claims = {"stu_num": request.form["stu_num"], "is_teacher": False}
    return jwt.encode(claims, "k", algorithm="HS256")  # safe: Mass Assignment


def save_profile(db):
    profile = request.form.to_dict()
    db.insert(profile)  # safe: Mass Assignment
    return create_token({"user": profile.get("user")})  # safe: Mass Assignment
