import datetime
from functools import wraps

import jwt
import psycopg2
from psycopg2 import Error as PGError
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SECRET_KEY = "super-secret-demo-key"
TOKEN_EXP_MINUTES = 60          # JWT lifetime (minutes)

DB_CONFIG = {
    "user":     "postgres",
    "password": "12345678",
    "host":     "localhost",
    "port":     "5432",
    "database": "projeto2025",
}


def connect_db():
    """Open a new PostgreSQL connection."""
    return psycopg2.connect(**DB_CONFIG)


# ---------------------------------------------------------------------------
# Basic user utilities
# ---------------------------------------------------------------------------
def fetch_user(username: str):
    """Return (user_id, user_name, password, email) for *username*, or None."""
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id, user_name, password, email
                  FROM user_
                 WHERE user_name = %s
                """,
                (username,),
            )
            return cur.fetchone()


def generate_token(user_id: int, username: str) -> str:
    """Issue a short-lived JWT."""
    payload = {
        "user_id":  user_id,
        "username": username,
        "exp":      datetime.datetime.utcnow()
                    + datetime.timedelta(minutes=TOKEN_EXP_MINUTES),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token.decode() if isinstance(token, bytes) else token


def token_required(f):
    """Protect an endpoint with bearer-token auth."""
    @wraps(f)
    def _wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify(
                {"status": 400, "errors": ["Missing or malformed Authorization header"]}
            ), 400

        token = auth_header.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = payload        # Stash user data on the request
        except jwt.ExpiredSignatureError:
            return jsonify({"status": 400, "errors": ["Token has expired"]}), 400
        except (jwt.InvalidTokenError, Exception):
            return jsonify({"status": 400, "errors": ["Invalid authentication token"]}), 400
        return f(*args, **kwargs)

    return _wrapper
