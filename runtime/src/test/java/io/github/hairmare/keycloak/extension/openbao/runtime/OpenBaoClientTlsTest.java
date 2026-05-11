package io.github.hairmare.keycloak.extension.openbao.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Optional;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

class OpenBaoClientTlsTest {

    private static final char[] PASSWORD = "changeit".toCharArray();

    private HttpsServer server;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void shouldReadSecretOverTlsUsingCustomTrustStore() throws Exception {
        GeneratedStores serverStores = createServerStores();

        SSLContext serverContext = serverSslContext(serverStores.keyStore(), PASSWORD, null, false);
        server = startServer(serverContext, false);

        SSLContext clientContext = OpenBaoTlsContextFactory.create(
            serverStores.trustStore().toString(),
                new String(PASSWORD),
                "PKCS12",
                null,
                null,
                "PKCS12",
                null);

        OpenBaoClient client = new OpenBaoClient(
                URI.create("https://localhost:" + server.getAddress().getPort()),
                "secret",
                "token",
                null,
                Duration.ofSeconds(1),
                Duration.ofSeconds(2),
                clientContext,
                false);

        Optional<String> secret = client.readSecret("db_password", "value");
        assertTrue(secret.isPresent());
        assertEquals("tls-secret", secret.get());
    }

    @Test
    void shouldReadSecretOverMutualTlsWithClientCertificate() throws Exception {
        GeneratedStores serverStores = createServerStores();
        GeneratedStores clientStores = createClientStores();

        SSLContext serverContext = serverSslContext(serverStores.keyStore(), PASSWORD, clientStores.trustStore(), true);
        server = startServer(serverContext, true);

        SSLContext clientContext = OpenBaoTlsContextFactory.create(
            serverStores.trustStore().toString(),
                new String(PASSWORD),
                "PKCS12",
            clientStores.keyStore().toString(),
                new String(PASSWORD),
                "PKCS12",
                new String(PASSWORD));

        OpenBaoClient client = new OpenBaoClient(
                URI.create("https://localhost:" + server.getAddress().getPort()),
                "secret",
                "token",
                null,
                Duration.ofSeconds(1),
                Duration.ofSeconds(2),
                clientContext,
                false);

        Optional<String> secret = client.readSecret("api_key", "value");
        assertTrue(secret.isPresent());
        assertEquals("tls-secret", secret.get());
    }

    private HttpsServer startServer(SSLContext sslContext, boolean requireClientAuth) throws IOException {
        HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress(0), 0);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters defaultParams = sslContext.getDefaultSSLParameters();
                params.setSSLParameters(defaultParams);
                params.setNeedClientAuth(requireClientAuth);
            }
        });

        httpsServer.createContext("/v1/secret/data/db_password", exchange ->
                writeJson(exchange, "{\"data\":{\"data\":{\"value\":\"tls-secret\"}}}"));
        httpsServer.createContext("/v1/secret/data/api_key", exchange ->
                writeJson(exchange, "{\"data\":{\"data\":{\"value\":\"tls-secret\"}}}"));
        httpsServer.start();
        return httpsServer;
    }

    private static void writeJson(HttpExchange exchange, String json) throws IOException {
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, payload.length);
        try (OutputStream response = exchange.getResponseBody()) {
            response.write(payload);
        }
    }

    private static SSLContext serverSslContext(Path keyStorePath, char[] keyStorePassword, Path trustStorePath, boolean needClientAuth)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(keyStorePath)) {
            keyStore.load(in, keyStorePassword);
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyStorePassword);

        TrustManagerFactory tmf = null;
        if (needClientAuth && trustStorePath != null) {
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            try (var in = Files.newInputStream(trustStorePath)) {
                trustStore.load(in, keyStorePassword);
            }
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
        }

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), tmf == null ? null : tmf.getTrustManagers(), new SecureRandom());
        return context;
    }

    private static GeneratedStores createServerStores() throws Exception {
        return createGeneratedStores("server", "CN=localhost", "localhost");
    }

    private static GeneratedStores createClientStores() throws Exception {
        return createGeneratedStores("client", "CN=openbao-client", null);
    }

    private static GeneratedStores createGeneratedStores(String alias, String distinguishedName, String sanHost)
            throws Exception {
        Path directory = Files.createTempDirectory(alias);
        Path keyStore = directory.resolve(alias + ".p12");
        Path certificate = directory.resolve(alias + ".crt");
        Path trustStore = directory.resolve(alias + "-trust.p12");

        if (sanHost == null) {
            runKeytool(
                    "-genkeypair",
                    "-alias", alias,
                    "-keyalg", "RSA",
                    "-keysize", "2048",
                    "-validity", "2",
                    "-storetype", "PKCS12",
                    "-keystore", keyStore.toString(),
                    "-storepass", new String(PASSWORD),
                    "-keypass", new String(PASSWORD),
                    "-dname", distinguishedName,
                    "-noprompt");
        } else {
            runKeytool(
                "-genkeypair",
                "-alias", alias,
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "2",
                "-storetype", "PKCS12",
                "-keystore", keyStore.toString(),
                "-storepass", new String(PASSWORD),
                "-keypass", new String(PASSWORD),
                "-dname", distinguishedName,
                "-noprompt",
                "-ext", "SAN=dns:" + sanHost + ",ip:127.0.0.1");
            }

        runKeytool(
                "-exportcert",
                "-alias", alias,
                "-storetype", "PKCS12",
                "-keystore", keyStore.toString(),
                "-storepass", new String(PASSWORD),
                "-rfc",
                "-file", certificate.toString());

        runKeytool(
                "-importcert",
                "-alias", alias,
                "-storetype", "PKCS12",
                "-keystore", trustStore.toString(),
                "-storepass", new String(PASSWORD),
                "-noprompt",
                "-file", certificate.toString());

        return new GeneratedStores(keyStore, trustStore);
    }

    private static void runKeytool(String... arguments) throws Exception {
        String keytoolExecutable = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        String[] command = new String[arguments.length + 1];
        command[0] = keytoolExecutable;
        System.arraycopy(arguments, 0, command, 1, arguments.length);

        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .start();

        byte[] output = process.getInputStream().readAllBytes();
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IllegalStateException("keytool failed with exit code " + exitCode + ": "
                    + new String(output, StandardCharsets.UTF_8));
        }
    }

    private record GeneratedStores(Path keyStore, Path trustStore) {
    }
}
