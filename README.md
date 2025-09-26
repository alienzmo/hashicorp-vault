
---

# 🔐 Vault-Flask-Auth

A secure, scalable authentication system built with **HashiCorp Vault**, **Flask**, **Redis**, and **JWT**.
This project demonstrates how to manage secrets, authenticate users, and issue tokens in a modern microservices environment using Vault as the central secrets manager.

---

## 📁 Project Structure

```
vault-flask-auth/
├─ app.py                        # Flask API implementation
├─ Dockerfile                   # Docker image for the Flask API
├─ requirements.txt             # Python dependencies
├─ docker-compose.yml           # Multi-container setup (Vault, Redis, Flask)
├─ vault/
│  ├─ policy.hcl                # Vault policy file
│  └─ init_vault.sh            # Vault initialization script
├─ postman/
│  └─ VaultFlaskAuth.postman_collection.json  # API test collection
├─ README.md
└─ .gitignore
```

---

## 🚀 Features

* ✅ Secure secret management with **HashiCorp Vault**
* 🔑 Authentication using **AppRole**
* 🔁 Token-based auth with **JWT**
* 🧠 High-speed session & refresh token storage using **Redis**
* 🔄 Dynamic secrets management and token rotation
* 🧪 Ready-to-use **Postman collection** for API testing
* 🐳 Containerized setup using **Docker Compose**

---

## 🛠️ Prerequisites

* Docker & Docker Compose
* Python 3.11+
* `jq` CLI tool (for parsing JSON in `init_vault.sh`)

---

## ⚙️ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/your-username/vault-flask-auth.git
cd vault-flask-auth
```

### 2. Create required directories

```bash
mkdir -p vault/data vault/config
cp vault/policy.hcl vault/config/policy.hcl
chmod +x vault/init_vault.sh
```

### 3. Start the environment

```bash
docker compose up -d
```

Wait a few seconds for the containers (`vault`, `redis`, and `auth-api`) to start.

---

## 🔑 Initialize Vault

Run the Vault initialization script:

```bash
./vault/init_vault.sh
```

This will:

* Initialize and unseal Vault
* Enable **AppRole** and **KV v2**
* Write secrets (e.g., `APP_JWT_SECRET` and `REDIS_PASSWORD`)
* Create a role and generate `ROLE_ID` and `SECRET_ID`

Copy the printed `ROLE_ID` and `SECRET_ID` values.

---

## 🧪 Configure Environment Variables

Create a `.env` file in the project root:

```env
VAULT_ADDR=http://127.0.0.1:8200
VAULT_ROLE_ID=<put-role-id-here>
VAULT_SECRET_ID=<put-secret-id-here>
REDIS_HOST=redis
REDIS_PORT=6379
ACCESS_TOKEN_EXPIRE=300
REFRESH_TOKEN_EXPIRE=604800
```

---

## ▶️ Start the API Service

Build and run the Flask service:

```bash
docker compose up -d --build auth-api
```

---

## 📡 API Endpoints

| Endpoint   | Method | Description                                |
| ---------- | ------ | ------------------------------------------ |
| `/signup`  | POST   | Register a new user                        |
| `/signin`  | POST   | Authenticate user and get tokens           |
| `/refresh` | POST   | Issue new access token using refresh token |
| `/logout`  | POST   | Invalidate refresh token                   |

---

## 📬 Example Requests (via `curl`)

**Signup**

```bash
curl -X POST http://localhost:5000/signup \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "secret123"}'
```

**Signin**

```bash
curl -X POST http://localhost:5000/signin \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "secret123"}'
```

**Refresh Token**

```bash
curl -X POST http://localhost:5000/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<your_refresh_token>"}'
```

**Logout**

```bash
curl -X POST http://localhost:5000/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<your_refresh_token>"}'
```

---

## 🧪 Testing with Postman

Import the provided collection:

```
postman/VaultFlaskAuth.postman_collection.json
```

It contains ready-to-use requests for all four endpoints.

---

## 🛡️ Security Recommendations (Production)

* ✅ Enable **TLS** in Vault configuration
* 🔐 Use **Shamir’s Secret Sharing** for unseal keys
* 🔄 Enable **token TTL** and **rotation policies**
* 📜 Enable full **audit logging**
* 🌐 Restrict network access via firewall/VPN
* 🔑 Use secure auth methods like **OIDC**, **JWT**, or **AppRole**

---

## 📈 Future Improvements

* 🔐 Add Multi-Factor Authentication (MFA)
* 📊 Implement advanced auditing and monitoring
* 🧩 Expand architecture to support multiple microservices
* ☁️ Integrate with GitLab CI/CD and Terraform for automation

---

## 📚 References

* [Vault Documentation](https://developer.hashicorp.com/vault/docs)
* [Redis Docs](https://redis.io/documentation)
* [Flask Docs](https://flask.palletsprojects.com/)
* [JWT.io](https://jwt.io/)
* [Docker Docs](https://docs.docker.com/)
* [Kubernetes Docs](https://kubernetes.io/docs/home/)
* [Keycloak Docs](https://www.keycloak.org/documentation)

---


Would you like me to generate this README as a downloadable **`README.md`** file? (So you can directly add it to your repo)
