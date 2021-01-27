path "sys/mounts" {
  capabilities = ["read"]
}

path "secret/*" {
  capabilities = ["read", "list"]
}

path "sys/renew/*" {
  capabilities = ["update"]
}
