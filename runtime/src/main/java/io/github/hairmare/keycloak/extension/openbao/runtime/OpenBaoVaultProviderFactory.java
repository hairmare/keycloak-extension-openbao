package io.github.hairmare.keycloak.extension.openbao.runtime;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import javax.net.ssl.SSLContext;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.vault.VaultKeyResolver;
import org.keycloak.vault.VaultProvider;
import org.keycloak.vault.VaultProviderFactory;

public class OpenBaoVaultProviderFactory implements VaultProviderFactory {

    private static final Logger LOG = Logger.getLogger(OpenBaoVaultProviderFactory.class);

    static final String PROVIDER_ID = "openbao";

    private static final String KEY_ADDRESS = "address";
    private static final String KEY_TOKEN = "token";
    private static final String KEY_TOKEN_FILE = "tokenFile";
    private static final String KEY_NAMESPACE = "namespace";
    private static final String KEY_MOUNT_PATH = "mountPath";
    private static final String KEY_SECRET_FIELD = "secretField";
    private static final String KEY_KEY_RESOLVERS = "keyResolvers";
    private static final String KEY_CONNECT_TIMEOUT_MILLIS = "connectTimeoutMillis";
    private static final String KEY_READ_TIMEOUT_MILLIS = "readTimeoutMillis";
    private static final String KEY_FACTORY_KEY_TEMPLATE = "factoryKeyTemplate";
    private static final String KEY_TLS_DISABLE_HOSTNAME_VERIFICATION = "tlsDisableHostnameVerification";
    private static final String KEY_TRUSTSTORE_FILE = "trustStoreFile";
    private static final String KEY_TRUSTSTORE_PASSWORD = "trustStorePassword";
    private static final String KEY_TRUSTSTORE_TYPE = "trustStoreType";
    private static final String KEY_KEYSTORE_FILE = "keyStoreFile";
    private static final String KEY_KEYSTORE_PASSWORD = "keyStorePassword";
    private static final String KEY_KEYSTORE_TYPE = "keyStoreType";
    private static final String KEY_KEYSTORE_KEY_PASSWORD = "keyStoreKeyPassword";

    private static final String DEFAULT_MOUNT_PATH = "secret";
    private static final String DEFAULT_SECRET_FIELD = "value";
    private static final long DEFAULT_CONNECT_TIMEOUT_MILLIS = 2_000L;
    private static final long DEFAULT_READ_TIMEOUT_MILLIS = 5_000L;
    private static final String DEFAULT_STORE_TYPE = "PKCS12";

    private OpenBaoClient client;
    private List<VaultKeyResolver> keyResolvers = Collections.emptyList();
    private String secretField = DEFAULT_SECRET_FIELD;

    @Override
    public VaultProvider create(KeycloakSession session) {
        if (client == null) {
            LOG.debug("OpenBao vault provider is disabled due to missing mandatory configuration");
            return null;
        }

        String realmName = "master";
        if (session != null && session.getContext() != null && session.getContext().getRealm() != null
                && session.getContext().getRealm().getName() != null) {
            realmName = session.getContext().getRealm().getName();
        }

        return new OpenBaoVaultProvider(realmName, keyResolvers, client, secretField);
    }

    @Override
    public void init(Config.Scope config) {
        String address = firstNonBlank(config.get(KEY_ADDRESS), config.get("url"));
        String token = firstNonBlank(config.get(KEY_TOKEN), readTokenFromFile(config.get(KEY_TOKEN_FILE)));
        if (address == null || token == null) {
            LOG.warnf("OpenBao vault provider is not configured. Required properties: %s and %s or %s", KEY_ADDRESS,
                    KEY_TOKEN, KEY_TOKEN_FILE);
            client = null;
            return;
        }

        String mountPath = config.get(KEY_MOUNT_PATH, DEFAULT_MOUNT_PATH);
        this.secretField = config.get(KEY_SECRET_FIELD, DEFAULT_SECRET_FIELD);

        long connectTimeoutMillis = config.getLong(KEY_CONNECT_TIMEOUT_MILLIS, DEFAULT_CONNECT_TIMEOUT_MILLIS);
        long readTimeoutMillis = config.getLong(KEY_READ_TIMEOUT_MILLIS, DEFAULT_READ_TIMEOUT_MILLIS);
        String namespace = config.get(KEY_NAMESPACE);
        boolean disableHostnameVerification = config.getBoolean(KEY_TLS_DISABLE_HOSTNAME_VERIFICATION, false);

        SSLContext sslContext = OpenBaoTlsContextFactory.create(
            config.get(KEY_TRUSTSTORE_FILE),
            config.get(KEY_TRUSTSTORE_PASSWORD),
            config.get(KEY_TRUSTSTORE_TYPE, DEFAULT_STORE_TYPE),
            config.get(KEY_KEYSTORE_FILE),
            config.get(KEY_KEYSTORE_PASSWORD),
            config.get(KEY_KEYSTORE_TYPE, DEFAULT_STORE_TYPE),
            config.get(KEY_KEYSTORE_KEY_PASSWORD));

        String factoryTemplate = config.get(KEY_FACTORY_KEY_TEMPLATE, "${realm}_${key}");
        this.keyResolvers = resolveResolvers(config.get(KEY_KEY_RESOLVERS), factoryTemplate);

        this.client = new OpenBaoClient(
                URI.create(address),
                mountPath,
                token,
                namespace,
                Duration.ofMillis(connectTimeoutMillis),
                Duration.ofMillis(readTimeoutMillis),
                sslContext,
                disableHostnameVerification);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization actions required.
    }

    @Override
    public void close() {
        // No resources to close.
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    private String readTokenFromFile(String tokenFile) {
        if (tokenFile == null || tokenFile.isBlank()) {
            return null;
        }

        try {
            return Files.readString(Path.of(tokenFile)).trim();
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read token file " + tokenFile, e);
        }
    }

    private List<VaultKeyResolver> resolveResolvers(String configuredResolvers, String factoryTemplate) {
        if (configuredResolvers == null || configuredResolvers.isBlank()) {
            return List.of(ResolverName.REALM_UNDERSCORE_KEY.resolver(factoryTemplate));
        }

        String[] names = configuredResolvers.split("\\s*,\\s*");
        List<VaultKeyResolver> resolved = new ArrayList<>(names.length);
        for (String name : names) {
            if (name == null || name.isBlank()) {
                continue;
            }

            ResolverName resolverName = ResolverName.fromConfigName(name);
            if (resolverName == null) {
                LOG.debugf("Unknown key resolver %s configured for OpenBao provider", name);
                continue;
            }

            resolved.add(resolverName.resolver(factoryTemplate));
        }

        if (resolved.isEmpty()) {
            throw new IllegalStateException("At least one valid key resolver must be configured");
        }

        return List.copyOf(resolved);
    }

    private String firstNonBlank(String first, String second) {
        if (first != null && !first.isBlank()) {
            return first;
        }
        if (second != null && !second.isBlank()) {
            return second;
        }
        return null;
    }

    enum ResolverName {
        KEY_ONLY,
        REALM_UNDERSCORE_KEY,
        REALM_FILESEPARATOR_KEY,
        FACTORY_PROVIDED;

        VaultKeyResolver resolver(String template) {
            switch (this) {
                case KEY_ONLY:
                    return (realm, key) -> escapeUnderscores(key);
                case REALM_UNDERSCORE_KEY:
                    return (realm, key) -> escapeUnderscores(realm) + "_" + escapeUnderscores(key);
                case REALM_FILESEPARATOR_KEY:
                    return (realm, key) -> realm + "/" + key;
                case FACTORY_PROVIDED:
                    return (realm, key) -> applyTemplate(template, realm, key);
                default:
                    throw new IllegalStateException("Unsupported resolver " + this);
            }
        }

        static ResolverName fromConfigName(String name) {
            try {
                return ResolverName.valueOf(name.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException ex) {
                return null;
            }
        }

        private static String applyTemplate(String template, String realm, String key) {
            String effectiveTemplate = Objects.requireNonNullElse(template, "${realm}_${key}");
            return effectiveTemplate
                    .replace("${realm}", realm)
                    .replace("${key}", key);
        }

        private static String escapeUnderscores(String value) {
            return value == null ? "" : value.replace("_", "__");
        }
    }
}
