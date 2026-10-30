from flask import Flask, request, session
import uuid

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login_vuln():
    # grants a session for whatever username was supplied, with no
    # credential check of any kind anywhere in this function at all —
    # the stubborne-style bug this check exists for. (Careful: don't
    # name the specific missing check by its usual literal term here, or
    # this comment would suppress the very finding it exists to assert
    # — the same self-referential trap this project has hit before.)
    username = request.form.get("username")
    session["user_id"] = username  # ruleid: Missing Authentication Check
    return "ok"


@app.route("/login/safe", methods=["POST"])
def login_safe():
    username = request.form.get("username")
    password = request.form.get("password")
    user = User.query.filter_by(username=username).first()
    # a real (if simplistic) credential check — must NOT fire even though
    # the shape (reads username, grants a session) is otherwise identical.
    if not user or not check_password_hash(user.password_hash, password):
        return "invalid credentials", 401
    session["user_id"] = user.id  # safe: Missing Authentication Check
    return "ok"


@app.route("/refresh", methods=["POST"])
def refresh_session():
    # grants a new session, but never reads a username/identity claim at
    # all — refreshing an already-established session is a different
    # shape than logging in, and outside what this check is about.
    session["session_id"] = str(uuid.uuid4())  # safe


@app.route("/profile")
def view_profile():
    # reads a username, but never grants a session for it — just a lookup.
    username = request.args.get("username")
    return User.query.filter_by(username=username).first().to_json()  # safe
