# key-vault

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fbloxapp%2Fkey-vault.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fbloxapp%2Fkey-vault?ref=badge_shield)

## Latest Image Digest

Latest verified image digest hosted on Docker Hub.
<!-- /TAG_START_MARKER/ -->
```bloxstaking/key-vault-rc:v1.5.1,bloxstaking/key-vault-rc:latest```
<!-- /TAG_END_MARKER/ -->
Use this hash when you `docker run` the image.
<!-- /DIGEST_START_MARKER/ -->
```sha256:a763d813ae9e4e5db37d3350f4e666445da2f1bc67a429bc8309b15be3357ea5```
<!-- /DIGEST_END_MARKER/ -->

## How to run?

Use docker run with the latest verified image digest:
<!-- /CMD_START_MARKER/ -->
```sh
ֿֿ$ docker run -d --restart unless-stopped --cap-add=IPC_LOCK --name=key_vault\ 
  -v $(pwd)/data:/data -v $(pwd)/policies:/policies -p 8200:8200\ 
  -e VAULT_ADDR='http://127.0.0.1:8200/' -e VAULT_API_ADDR='http://127.0.0.1:8200/'\ 
  -e VAULT_CLIENT_TIMEOUT='30s' -e UNSEAL=true bloxstaking/key-vault@sha256:a763d813ae9e4e5db37d3350f4e666445da2f1bc67a429bc8309b15be3357ea5
```
<!-- /CMD_END_MARKER/ -->

## How to build from source (development purposes)?

1. Build the images and run the containers:

      ```sh
      $ docker-compose up -d --build
      ```

2. Execute the container

      ```sh
      $ docker-compose exec vault bash
      ```

3. Read the root token

      ```sh
      $ docker-compose exec -T vault cat /data/keys/vault.root.token
      ```

## Endpoints


### GET VERSION

This endpoint will get a version of key-vault.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `GET`  | `:mount-path/:network/version`  | `200 application/json` |


#### Sample Response

The example below shows output for a query path of `/ethereum/prater/version`.

```
{
    "request_id": "b68953bf-811e-f218-a1c4-b5a7aa4122bc",
    "lease_id": "",
    "renewable": false,
    "lease_duration": 0,
    "data": {
        "version": "v1.1.1"
    },
    "wrap_info": null,
    "warnings": null,
    "auth": null
}
```

### LIST ACCOUNTS

This endpoint will list all accounts of key-vault.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `LIST`  | `:mount-path/:network/accounts`  | `200 application/json` |


#### Sample Response

The example below shows output for a query path of `/ethereum/prater/accounts` when there is 1 account.

```
{
    "request_id": "489790dc-b4bd-54e5-be6e-95a894ffc48c",
    "lease_id": "",
    "renewable": false,
    "lease_duration": 0,
    "data": {
        "accounts": [
            {
                "id": "9676ef06-d238-49f3-ab50-b3fe9930db0f",
                "name": "account-0",
                "validationPubKey": "8a5df36be5f89f9fe19cabadcbb17babc8c518bcd7fe0095c89f83915ea943343fa7dd3c26d8fb6096bce11fbc1ec7d3",
                "withdrawalPubKey": "887abb059075160ce2556a8bfef745898ee3a11b2b6521b09077d422c164929dea277ac8afcacd5b6d729198238f8f6c"
            }
        ]
    },
    "wrap_info": null,
    "warnings": null,
    "auth": null
}
```

### UPDATE STORAGE

This endpoint will update the storage.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `POST`  | `:mount-path/:network/storage`  | `200 application/json` |


#### Sample Response

The example below shows output for a query path of `/ethereum/prater/storage`.

```
{
    {
        "request_id": "d53d5075-6a3b-2642-ffde-0714beb595f5",
        "lease_id": "",
        "renewable": false,
        "lease_duration": 0,
        "data": {
            "status": true
        },
        "wrap_info": null,
        "warnings": null,
        "auth": null
    }
}
```

### READ SLASHING STORAGE

This endpoint will update the storage.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `GET`  | `:mount-path/:network/storage/slashing`  | `200 application/json` |


#### Sample Response

The example below shows output for a query path of `/ethereum/prater/storage/slashing`.

```
{
    {
        "request_id": "d53d5075-6a3b-2642-ffde-0714beb595f5",
        "lease_id": "",
        "renewable": false,
        "lease_duration": 0,
        "data": {
            "<public_key>": "<hex_encoded_slashing_storage>"
        },
        "wrap_info": null,
        "warnings": null,
        "auth": null
    }
}
```

### SIGN ATTESTATION

This endpoint will sign attestation for specific account at a path.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `POST`  | `:mount-path/:network/accounts/sign`  | `200 application/json` |

#### Parameters

* `public_key` (`string: <required>`) - Specifies the public key of the account to sign.
* `domain` (`string: <required>`) - Specifies the domain.
* `slot` (`int: <required>`) - Specifies the slot.
* `committeeIndex` (`int: <required>`) - Specifies the committeeIndex.
* `beaconBlockRoot` (`string: <required>`) - Specifies the beaconBlockRoot.
* `sourceEpoch` (`int: <required>`) - Specifies the sourceEpoch.
* `sourceRoot` (`string: <required>`) - Specifies the sourceRoot.
* `targetEpoch` (`int: <required>`) - Specifies the targetEpoch.
* `targetRoot` (`string: <required>`) - Specifies the targetRoot.

#### Sample Response

The example below shows output for the successful sign of `/ethereum/accounts/sign`.

```
{
    "request_id": "b767dcca-5b10-4a52-1d9a-0a9b81b378ae",
    "lease_id": "",
    "renewable": false,
    "lease_duration": 0,
    "data": {
        "signature": "kEEOMxNkouz7EOSULfrG6hXzZbIOvRCVVK+lfBofj3U49/PHm7YHji8ac9Gf9vgEFVEmbPp+lhO3OpAElt3yaBajTKaJBWocgXuv64Ojq44tfxLJo6jrzMU5yoP78dYW"
    },
    "wrap_info": null,
    "warnings": null,
    "auth": null
}
```

## Access Policies
The plugin's endpoint paths are designed such that admin-level access policies vs. signer-level access policies can be easily separated.

### Sample Signer Level Policy:
Use the following policy to assign to a signer level access token, with the abilities to list accounts and sign transactions.

```
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
```

### Sample Admin Level Policy:
Use the following policy to assign to a admin level access token, with the full ability to update storage, list accounts and sign transactions.

```
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
```

## How to use policies?

1. Create a new policy named admin:

      ```sh
      $ vault policy write admin policies/admin-policy.hcl
      ```

2. Create a token attached to admin policy:

      ```sh
      $ vault token create -policy="admin"
      ```

3. Create a new policy named signer:

      ```sh
      $ vault policy write signer policies/signer-policy.hcl
      ```

4. Create a token attached to signer policy:

      ```sh
      $ vault token create -policy="signer"
      ```

## About testing

There are 2 types of tests in the project: end-to-end and unit ones.
In order to run all tests including e2e ones you will need to do the following command:
```bash
$ make full-test
``` 

New e2e tests should be placed in `./e2e/tests` directory and implement `E2E` interface.
Use the current format to add new tests.


## Release Version

versions are published to dockerhub based on tags.
before publishing a tag update docker compose image to the to be pushed tag

## Multinetworks

The plugin supports multiple Ethereum networks. All available networks are defined in `./config/vault-plugin.sh`.
New networks could be defined by the following steps:

1. Enable secrets for a new network in `./config/vault-plugin.sh`.
   Example
    ```bash
    $ vault secrets enable \
        -path=ethereum/prater \
        -description="Eth Signing Wallet - Prater Test Network" \
        -plugin-name=ethsign plugin > /dev/null 2>  &1
    ```

2. Update policies `./policies/admin-policy.hcl` and `./policies/signer-policy.hcl` by adding a definition with a new network in the path.
