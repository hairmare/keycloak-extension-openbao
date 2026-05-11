package io.github.hairmare.keycloak.extension.openbao.runtime;

import java.io.File;
import java.util.List;
import java.util.Optional;

import org.jboss.logging.Logger;
import org.keycloak.vault.VaultKeyResolver;
import org.keycloak.vault.VaultProvider;
import org.keycloak.vault.VaultRawSecret;

final class OpenBaoVaultProvider implements VaultProvider {

    private static final Logger LOG = Logger.getLogger(OpenBaoVaultProvider.class);

    private final String realm;
    private final List<VaultKeyResolver> resolvers;
    private final OpenBaoClient client;
    private final String secretField;

    OpenBaoVaultProvider(String realm, List<VaultKeyResolver> resolvers, OpenBaoClient client, String secretField) {
        this.realm = realm;
        this.resolvers = resolvers;
        this.client = client;
        this.secretField = secretField;
    }

    @Override
    public VaultRawSecret obtainSecret(String vaultSecretId) {
        if (vaultSecretId == null || vaultSecretId.isBlank()) {
            return ByteArrayVaultRawSecret.empty();
        }

        for (VaultKeyResolver resolver : resolvers) {
            String resolvedKey = resolver.apply(realm, vaultSecretId);
            if (!validate(vaultSecretId, resolvedKey)) {
                return ByteArrayVaultRawSecret.empty();
            }
        }

        for (VaultKeyResolver resolver : resolvers) {
            String resolvedKey = resolver.apply(realm, vaultSecretId);
            try {
                Optional<String> secretValue = client.readSecret(resolvedKey, secretField);
                if (secretValue.isPresent()) {
                    return ByteArrayVaultRawSecret.fromString(secretValue.get());
                }
            } catch (RuntimeException ex) {
                LOG.warnf(ex, "Unable to resolve secret %s using key %s", vaultSecretId, resolvedKey);
                return ByteArrayVaultRawSecret.empty();
            }
        }

        return ByteArrayVaultRawSecret.empty();
    }

    private boolean validate(String key, String resolvedKey) {
        if (key.contains(File.separator) || key.contains("/") || key.contains("\\")) {
            LOG.warnf("Key %s contains path separator characters and is rejected", key);
            return false;
        }

        if (resolvedKey == null || resolvedKey.isBlank()) {
            LOG.warnf("Resolved key for %s is blank", key);
            return false;
        }

        return true;
    }

    @Override
    public void close() {
        // No state to close.
    }
}
