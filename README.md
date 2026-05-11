# keycloak-extension-openbao

Quarkus extension that provides a [Keycloak Vault SPI](https://www.keycloak.org/server/vault) implementation backed by OpenBao KV v2.

## What it provides

- Keycloak Vault SPI provider id: `openbao`
- Native OpenBao HTTP API integration (`/v1/<mount>/data/<path>`)
- Key resolver strategies compatible with Keycloak vault placeholders
- Secret lookup fallback across multiple resolvers in configured order
- In-memory secret wiping via `VaultRawSecret.close()`

## Configuration

The provider is configured through Keycloak SPI vault settings.

Required settings:

- `spi-vault-openbao-address`
- one of:
  - `spi-vault-openbao-token`
  - `spi-vault-openbao-tokenFile`

Optional settings:

- `spi-vault-openbao-mountPath` (default: `secret`)
- `spi-vault-openbao-secretField` (default: `value`)
- `spi-vault-openbao-keyResolvers` (default: `REALM_UNDERSCORE_KEY`)
- `spi-vault-openbao-factoryKeyTemplate` (used when `FACTORY_PROVIDED` is configured)
- `spi-vault-openbao-connectTimeoutMillis` (default: `2000`)
- `spi-vault-openbao-readTimeoutMillis` (default: `5000`)
- `spi-vault-openbao-namespace` (optional header `X-Vault-Namespace`)
- `spi-vault-openbao-tlsDisableHostnameVerification` (default: `false`)

TLS trust material options:

- `spi-vault-openbao-trustStoreFile`
- `spi-vault-openbao-trustStorePassword`
- `spi-vault-openbao-trustStoreType` (default: `PKCS12`)

mTLS client certificate options:

- `spi-vault-openbao-keyStoreFile`
- `spi-vault-openbao-keyStorePassword`
- `spi-vault-openbao-keyStoreType` (default: `PKCS12`)
- `spi-vault-openbao-keyStoreKeyPassword` (defaults to `keyStorePassword` when omitted)

Supported `keyResolvers` values:

- `KEY_ONLY`
- `REALM_UNDERSCORE_KEY`
- `REALM_FILESEPARATOR_KEY`
- `FACTORY_PROVIDED`

## Example

```properties
spi-vault-provider=openbao
spi-vault-openbao-address=http://127.0.0.1:8200
spi-vault-openbao-token=replace-with-token
spi-vault-openbao-mountPath=secret
spi-vault-openbao-secretField=value
spi-vault-openbao-keyResolvers=REALM_UNDERSCORE_KEY,KEY_ONLY
```

With a realm named `acme` and `${vault.db_password}` in Keycloak config, the resolver `REALM_UNDERSCORE_KEY` produces `acme_db__password` and reads from:

- `GET /v1/secret/data/acme_db__password`

## Testing

Runtime tests cover:

- OpenBao response parsing and header handling
- Resolver ordering and fallback behavior
- Factory initialization and provider creation paths
- TLS trust store and mTLS client certificate flows

End-to-end container tests are provided in the `integration-tests` module and are disabled by default.

Run them with:

```bash
mvn -Pe2e verify
```

These tests start OpenBao and Keycloak containers, load the built provider jar into Keycloak, and verify Keycloak starts with the OpenBao vault provider enabled.

When running locally, point Testcontainers at your Podman machine socket before invoking the e2e profile.
