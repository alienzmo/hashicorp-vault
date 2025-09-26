path "secret/data/myapp" {
  capabilities = ["read"]
}

#if you need to read from creds:
# path "database/creds/*" {
#   capabilities = ["read"]
# }
