package io.github.hairmare.keycloak.extension.openbao.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.vault.VaultProvider;

class OpenBaoVaultProviderFactoryTest {

    @Test
    void shouldCreateProviderWhenConfigured() {
        OpenBaoVaultProviderFactory factory = new OpenBaoVaultProviderFactory();

        Config.Scope config = new MapScope(Map.of(
            "address", "http://127.0.0.1:8200",
            "token", "test-token",
            "mountPath", "secret",
            "secretField", "value",
            "connectTimeoutMillis", "500",
            "readTimeoutMillis", "500",
            "namespace", "ns-a",
            "keyResolvers", "REALM_UNDERSCORE_KEY,KEY_ONLY",
            "factoryKeyTemplate", "${realm}/${key}"));

        factory.init(config);

        VaultProvider provider = factory.create(null);

        assertNotNull(provider);
        assertEquals("openbao", factory.getId());
    }

    @Test
    void shouldDisableProviderWhenMandatorySettingsAreMissing() {
        OpenBaoVaultProviderFactory factory = new OpenBaoVaultProviderFactory();

        Config.Scope config = new MapScope(Collections.emptyMap());

        factory.init(config);

        assertNull(factory.create(null));
    }

    @Test
    void shouldApplyFactoryProvidedResolverTemplate() {
        OpenBaoVaultProviderFactory.ResolverName resolver = OpenBaoVaultProviderFactory.ResolverName.FACTORY_PROVIDED;

        String resolved = resolver.resolver("tenants/${realm}/secrets/${key}").apply("realm-a", "db-password");

        assertEquals("tenants/realm-a/secrets/db-password", resolved);
    }

    private static final class MapScope implements Config.Scope {
        private final Map<String, String> values;

        private MapScope(Map<String, String> values) {
            this.values = new HashMap<>(values);
        }

        @Override
        public String get(String key) {
            return values.get(key);
        }

        @Override
        public String get(String key, String defaultValue) {
            String value = values.get(key);
            return value == null ? defaultValue : value;
        }

        @Override
        public String[] getArray(String key) {
            String value = values.get(key);
            return value == null ? null : value.split("\\s*,\\s*");
        }

        @Override
        public Integer getInt(String key) {
            return getInt(key, null);
        }

        @Override
        public Integer getInt(String key, Integer defaultValue) {
            String value = values.get(key);
            return value == null ? defaultValue : Integer.valueOf(value);
        }

        @Override
        public Long getLong(String key) {
            return getLong(key, null);
        }

        @Override
        public Long getLong(String key, Long defaultValue) {
            String value = values.get(key);
            return value == null ? defaultValue : Long.valueOf(value);
        }

        @Override
        public Boolean getBoolean(String key) {
            return getBoolean(key, null);
        }

        @Override
        public Boolean getBoolean(String key, Boolean defaultValue) {
            String value = values.get(key);
            return value == null ? defaultValue : Boolean.valueOf(value);
        }

        @Override
        public Config.Scope scope(String... scope) {
            return this;
        }

        @Override
        @Deprecated
        public Set<String> getPropertyNames() {
            return values.keySet();
        }

        @Override
        public Config.Scope root() {
            return this;
        }
    }
}
