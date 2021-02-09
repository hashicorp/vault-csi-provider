path "secret/*" {
  capabilities = ["read"]
}

path "database/creds/test-role" {
  capabilities = ["read"]
}

path "pki/issue/example-dot-com" {
  capabilities = ["update"]
}
