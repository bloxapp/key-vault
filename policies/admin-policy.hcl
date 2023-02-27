# Ability to list prater wallet accounts ("list")
path "ethereum/prater/accounts" {
  capabilities = ["list"]
}

# Ability to list mainnet wallet accounts ("list")
path "ethereum/mainnet/accounts" {
  capabilities = ["list"]
}

# Ability to sign data ("create")
path "ethereum/+/accounts/sign" {
  capabilities = ["create"]
}

# Ability to get version ("read")
path "ethereum/+/version" {
  capabilities = ["read"]
}

# Ability to update storage ("create")
path "ethereum/+/storage" {
  capabilities = ["create"]
}

# Ability to read slashing storage ("read")
path "ethereum/+/storage/slashing" {
  capabilities = ["read"]
}

# Ability to create/update/read config
path "ethereum/+/config" {
  capabilities = ["create", "update", "read"]
}

# Ability to sign voluntary exit ("create")
path "ethereum/+/accounts/sign-voluntary-exit" {
  capabilities = ["create"]
}