package io.github.hairmare.keycloak.extension.openbao.test;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.keycloak.vault.VaultProviderFactory;

import io.github.hairmare.keycloak.extension.openbao.runtime.OpenBaoVaultProviderFactory;

import io.quarkus.test.QuarkusExtensionTest;

import java.util.ServiceLoader;

public class KeycloakExtensionOpenbaoTest {

    // Start unit test with your extension loaded
    @RegisterExtension
    static final QuarkusExtensionTest unitTest = new QuarkusExtensionTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class));

    @Test
    public void shouldRegisterOpenBaoVaultProviderFactory() {
        boolean found = ServiceLoader.load(VaultProviderFactory.class)
                .stream()
                .map(ServiceLoader.Provider::get)
                .anyMatch(factory -> factory instanceof OpenBaoVaultProviderFactory);

        Assertions.assertTrue(found, "OpenBao VaultProviderFactory should be discoverable through ServiceLoader");
    }
}
