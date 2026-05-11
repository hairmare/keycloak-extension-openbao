package io.github.hairmare.keycloak.extension.openbao.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

final class OpenBaoTlsContextFactory {

    private OpenBaoTlsContextFactory() {
    }

    static SSLContext create(
            String trustStoreFile,
            String trustStorePassword,
            String trustStoreType,
            String keyStoreFile,
            String keyStorePassword,
            String keyStoreType,
            String keyStoreKeyPassword) {

        if (isBlank(trustStoreFile) && isBlank(keyStoreFile)) {
            return null;
        }

        try {
            TrustManagerFactory trustManagerFactory = null;
            if (!isBlank(trustStoreFile)) {
                KeyStore trustStore = loadKeyStore(Path.of(trustStoreFile), trustStoreType, toPassword(trustStorePassword));
                trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustStore);
            }

            KeyManagerFactory keyManagerFactory = null;
            if (!isBlank(keyStoreFile)) {
                char[] keyStorePasswordChars = toPassword(keyStorePassword);
                KeyStore keyStore = loadKeyStore(Path.of(keyStoreFile), keyStoreType, keyStorePasswordChars);
                keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                char[] keyPassword = isBlank(keyStoreKeyPassword) ? keyStorePasswordChars : toPassword(keyStoreKeyPassword);
                keyManagerFactory.init(keyStore, keyPassword);
            }

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(
                    keyManagerFactory == null ? null : keyManagerFactory.getKeyManagers(),
                    trustManagerFactory == null ? null : trustManagerFactory.getTrustManagers(),
                    null);
            return sslContext;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("Failed to initialize OpenBao TLS context", e);
        }
    }

    private static KeyStore loadKeyStore(Path keyStorePath, String type, char[] password) throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance(isBlank(type) ? KeyStore.getDefaultType() : type);
        try (InputStream in = Files.newInputStream(keyStorePath)) {
            keyStore.load(in, password);
        }
        return keyStore;
    }

    private static char[] toPassword(String value) {
        return value == null ? null : value.toCharArray();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
