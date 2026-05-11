package io.github.hairmare.keycloak.extension.openbao.test;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.vault.VaultProviderFactory;

import io.github.hairmare.keycloak.extension.openbao.runtime.OpenBaoVaultProviderFactory;

import java.util.ServiceLoader;

public class KeycloakExtensionOpenbaoTest {

    @Test
    public void shouldRegisterOpenBaoVaultProviderFactory() {
        boolean found = ServiceLoader.load(VaultProviderFactory.class)
                .stream()
                .map(ServiceLoader.Provider::get)
                .anyMatch(factory -> factory instanceof OpenBaoVaultProviderFactory);

        Assertions.assertTrue(found, "OpenBao VaultProviderFactory should be discoverable through ServiceLoader");
    }
}
