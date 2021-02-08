path "secret/*" {
  capabilities = ["read"]
}

path "pki/issue/example-dot-com" {
  capabilities = ["update"]
}
