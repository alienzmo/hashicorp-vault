#!/bin/sh
set -e

VAULT_CLI="docker exec -i vault vault"

echo "Waiting for Vault..."
until docker exec vault sh -c "vault status" >/dev/null 2>&1; do
  sleep 1
done
echo "Vault is up"

IS_INIT=$(docker exec vault sh -c "vault status -format=json" | jq -r .initialized)
if [ "$IS_INIT" != "true" ]; then
  echo "Initializing Vault..."
  docker exec vault sh -c "vault operator init -key-shares=1 -key-threshold=1 -format=json" > /tmp/vault_init.json
  cat /tmp/vault_init.json
  UNSEAL_KEY=$(jq -r .unseal_keys_b64[0] /tmp/vault_init.json)
  ROOT_TOKEN=$(jq -r .root_token /tmp/vault_init.json)
  echo "Unseal key: $UNSEAL_KEY"
  echo "Root token: $ROOT_TOKEN"
  docker exec vault sh -c "vault operator unseal $UNSEAL_KEY"
  export VAULT_TOKEN=$ROOT_TOKEN
else
  echo "Vault already initialized"
fi

docker exec vault sh -c "export VAULT_ADDR='http://127.0.0.1:8200' && vault auth enable approle" || true

docker exec vault sh -c "vault policy write myapp-policy /vault/config/policy.hcl"

# enable kv v2 at secret/
docker exec vault sh -c "vault secrets enable -path=secret kv-v2" || true

docker exec vault sh -c "vault kv put secret/myapp APP_JWT_SECRET='replace-with-long-random-secret' REDIS_PASSWORD='redispassword'"

docker exec vault sh -c "vault write auth/approle/role/myapp token_ttl=30m token_max_ttl=1h policies=myapp-policy"

ROLE_ID=$(docker exec vault sh -c "vault read -field=role_id auth/approle/role/myapp/role-id")
SECRET_ID_JSON=$(docker exec vault sh -c "vault write -f -format=json auth/approle/role/myapp/secret-id")
SECRET_ID=$(echo "$SECRET_ID_JSON" | jq -r .data.secret_id)

echo "---------------------------"
echo "ROLE_ID: $ROLE_ID"
echo "SECRET_ID: $SECRET_ID"
echo "---------------------------"
echo "Now put these values into your .env or pass them as env vars to auth-api"
