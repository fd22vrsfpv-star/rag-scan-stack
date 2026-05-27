storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable   = false
  tls_cert_file = "/certs/server.crt"
  tls_key_file  = "/certs/server.key"
}

api_addr     = "https://vault:8200"
cluster_addr = "https://vault:8201"
ui           = true
disable_mlock = false
