package io.github.hairmare.keycloak.extension.openbao.runtime;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.vault.VaultRawSecret;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class OpenBaoVaultProviderTest {

    private HttpServer server;
    private URI baseUri;

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.start();
        baseUri = URI.create("http://localhost:" + server.getAddress().getPort());
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void shouldResolveSecretUsingFirstMatchingResolver() {
        AtomicInteger firstResolverHits = new AtomicInteger();
        server.createContext("/v1/secret/data/realm__a_db__password", exchange -> {
            firstResolverHits.incrementAndGet();
            writeJson(exchange, 200, "{\"data\":{\"data\":{\"value\":\"db-pass\"}}}");
        });

        OpenBaoClient client = new OpenBaoClient(baseUri, "secret", "token", null,
                Duration.ofSeconds(1), Duration.ofSeconds(1));

        OpenBaoVaultProvider provider = new OpenBaoVaultProvider(
                "realm_a",
                List.of(OpenBaoVaultProviderFactory.ResolverName.REALM_UNDERSCORE_KEY.resolver("${realm}_${key}")),
                client,
                "value");

        try (VaultRawSecret secret = provider.obtainSecret("db_password")) {
            assertTrue(secret.getAsArray().isPresent());
            assertArrayEquals("db-pass".getBytes(StandardCharsets.UTF_8), secret.getAsArray().orElseThrow());
            assertTrue(firstResolverHits.get() > 0);
        }
    }

    @Test
    void shouldTryMultipleResolversInOrder() {
        AtomicInteger keyOnlyHits = new AtomicInteger();
        AtomicInteger realmHits = new AtomicInteger();

        server.createContext("/v1/secret/data/api__key", exchange -> {
            keyOnlyHits.incrementAndGet();
            writeJson(exchange, 404, "{}");
        });
        server.createContext("/v1/secret/data/tenant_api__key", exchange -> {
            realmHits.incrementAndGet();
            writeJson(exchange, 200, "{\"data\":{\"data\":{\"value\":\"realm-secret\"}}}");
        });

        OpenBaoClient client = new OpenBaoClient(baseUri, "secret", "token", null,
                Duration.ofSeconds(1), Duration.ofSeconds(1));

        OpenBaoVaultProvider provider = new OpenBaoVaultProvider(
                "tenant",
                List.of(
                        OpenBaoVaultProviderFactory.ResolverName.KEY_ONLY.resolver("${realm}_${key}"),
                        OpenBaoVaultProviderFactory.ResolverName.REALM_UNDERSCORE_KEY.resolver("${realm}_${key}")),
                client,
                "value");

        try (VaultRawSecret secret = provider.obtainSecret("api_key")) {
            assertTrue(secret.get().isPresent());
            ByteBuffer value = secret.get().orElseThrow();
            assertArrayEquals("realm-secret".getBytes(StandardCharsets.UTF_8), toBytes(value));
            assertTrue(keyOnlyHits.get() > 0);
            assertTrue(realmHits.get() > 0);
        }
    }

    @Test
    void shouldRejectInvalidSecretKey() {
        OpenBaoClient client = new OpenBaoClient(baseUri, "secret", "token", null,
                Duration.ofSeconds(1), Duration.ofSeconds(1));

        OpenBaoVaultProvider provider = new OpenBaoVaultProvider(
                "tenant",
                List.of(OpenBaoVaultProviderFactory.ResolverName.KEY_ONLY.resolver("${realm}_${key}")),
                client,
                "value");

        try (VaultRawSecret secret = provider.obtainSecret("folder/password")) {
            assertTrue(secret.getAsArray().isEmpty());
        }
    }

    private static byte[] toBytes(ByteBuffer buffer) {
        ByteBuffer duplicate = buffer.duplicate();
        byte[] bytes = new byte[duplicate.remaining()];
        duplicate.get(bytes);
        return bytes;
    }

    private static void writeJson(HttpExchange exchange, int status, String payload) throws IOException {
        byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream body = exchange.getResponseBody()) {
            body.write(bytes);
        }
    }
}
