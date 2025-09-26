import os
import time
import json
import requests
import bcrypt
import jwt
import uuid
from flask import Flask, request, jsonify
import redis
from dotenv import load_dotenv

load_dotenv()

VAULT_ADDR = os.getenv("VAULT_ADDR")  # e.g. http://vault:8200
ROLE_ID = os.getenv("ROLE_ID")
SECRET_ID = os.getenv("SECRET_ID")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)  # if not set, will be read from Vault

# defaults
ACCESS_TOKEN_EXPIRE = int(os.getenv("ACCESS_TOKEN_EXPIRE", 300))  # seconds
REFRESH_TOKEN_EXPIRE = int(os.getenv("REFRESH_TOKEN_EXPIRE", 3600*24*7))  # one week

app = Flask(__name__)

# Redis client (we'll set password after reading Vault if needed)
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)

# Globals to be populated at startup
APP_JWT_SECRET = None

def vault_login_and_get_secrets():
    global APP_JWT_SECRET, REDIS_PASSWORD, r
    if not VAULT_ADDR or not ROLE_ID:
        raise Exception("Vault configuration missing")
    # first, login with approle. If SECRET_ID is not provided, call API to create one (optional)
    secret_id = SECRET_ID
    if not secret_id:
        # create one-time secret id (note: server-side policy matters)
        resp = requests.post(f"{VAULT_ADDR}/v1/auth/approle/role/myapp/secret-id")
        resp.raise_for_status()
        secret_id = resp.json()["data"]["secret_id"]

    login_resp = requests.post(f"{VAULT_ADDR}/v1/auth/approle/login", json={
        "role_id": ROLE_ID,
        "secret_id": secret_id
    })
    login_resp.raise_for_status()
    client_token = login_resp.json()["auth"]["client_token"]

    # read kv secret
    headers = {"X-Vault-Token": client_token}
    kv = requests.get(f"{VAULT_ADDR}/v1/secret/data/myapp", headers=headers)
    kv.raise_for_status()
    data = kv.json()["data"]["data"]
    APP_JWT_SECRET = data.get("APP_JWT_SECRET")
    redis_pwd = data.get("REDIS_PASSWORD")
    if redis_pwd and (not REDIS_PASSWORD):
        REDIS_PASSWORD = redis_pwd
        # reconnect redis if necessary
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)

# helper: create jwt
def create_access_token(username):
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + ACCESS_TOKEN_EXPIRE
    }
    token = jwt.encode(payload, APP_JWT_SECRET, algorithm="HS256")
    return token

@app.route("/signup", methods=["POST"])
def signup():
    body = request.json or {}
    username = body.get("username")
    password = body.get("password")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    if r.hexists("users", username):
        return jsonify({"error": "user exists"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    r.hset("users", username, hashed)
    return jsonify({"status":"ok"}), 201

@app.route("/signin", methods=["POST"])
def signin():
    body = request.json or {}
    username = body.get("username")
    password = body.get("password")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    stored = r.hget("users", username)
    if not stored:
        return jsonify({"error": "invalid credentials"}), 401

    if not bcrypt.checkpw(password.encode(), stored.encode()):
        return jsonify({"error": "invalid credentials"}), 401

    access = create_access_token(username)
    refresh = str(uuid.uuid4())
    # store refresh in redis with TTL
    r.set(f"refresh:{refresh}", username, ex=REFRESH_TOKEN_EXPIRE)
    return jsonify({"access_token": access, "refresh_token": refresh, "expires_in": ACCESS_TOKEN_EXPIRE})

@app.route("/refresh", methods=["POST"])
def refresh():
    body = request.json or {}
    refresh = body.get("refresh_token")
    if not refresh:
        return jsonify({"error": "refresh_token required"}), 400

    username = r.get(f"refresh:{refresh}")
    if not username:
        return jsonify({"error": "invalid or expired refresh token"}), 401

    access = create_access_token(username)
    return jsonify({"access_token": access, "expires_in": ACCESS_TOKEN_EXPIRE})

@app.route("/logout", methods=["POST"])
def logout():
    body = request.json or {}
    refresh = body.get("refresh_token")
    if not refresh:
        return jsonify({"error": "refresh_token required"}), 400

    r.delete(f"refresh:{refresh}")
    return jsonify({"status":"logged_out"})

if __name__ == "__main__":
    # on startup, login to Vault and read secrets
    # retry loop in case Vault not ready yet
    attempt = 0
    while attempt < 10:
        try:
            vault_login_and_get_secrets()
            break
        except Exception as e:
            attempt += 1
            print("Vault not ready yet, retrying...", e)
            time.sleep(2)
    if not APP_JWT_SECRET:
        print("ERROR: can't read APP_JWT_SECRET from Vault; exiting")
        raise SystemExit(1)
app.run(host="0.0.0.0", port=5000)
