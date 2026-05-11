package io.github.hairmare.keycloak.extension.openbao.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class OpenBaoClientTest {

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
    void shouldReadPreferredFieldAndSendHeaders() {
        AtomicReference<String> tokenHeader = new AtomicReference<>();
        AtomicReference<String> namespaceHeader = new AtomicReference<>();

        server.createContext("/v1/secret/data/test", exchange -> {
            tokenHeader.set(exchange.getRequestHeaders().getFirst("X-Vault-Token"));
            namespaceHeader.set(exchange.getRequestHeaders().getFirst("X-Vault-Namespace"));
            writeJson(exchange, 200, "{\"data\":{\"data\":{\"value\":\"s3cr3t\"}}}");
        });

        OpenBaoClient client = new OpenBaoClient(baseUri, "secret", "token-123", "team-a",
                Duration.ofSeconds(1), Duration.ofSeconds(1));

        Optional<String> secret = client.readSecret("test", "value");

        assertTrue(secret.isPresent());
        assertEquals("s3cr3t", secret.get());
        assertEquals("token-123", tokenHeader.get());
        assertEquals("team-a", namespaceHeader.get());
    }

    @Test
    void shouldFallBackToSingleEntryWhenPreferredFieldMissing() {
        server.createContext("/v1/secret/data/realm_key", exchange ->
                writeJson(exchange, 200, "{\"data\":{\"data\":{\"password\":\"fallback\"}}}"));

        OpenBaoClient client = new OpenBaoClient(baseUri, "secret", "token", null,
                Duration.ofSeconds(1), Duration.ofSeconds(1));

        Optional<String> secret = client.readSecret("realm_key", "value");

        assertTrue(secret.isPresent());
        assertEquals("fallback", secret.get());
    }

    @Test
    void shouldReturnEmptyOnNotFound() {
        server.createContext("/v1/secret/data/missing", exchange -> writeJson(exchange, 404, "{}"));

        OpenBaoClient client = new OpenBaoClient(baseUri, "secret", "token", null,
                Duration.ofSeconds(1), Duration.ofSeconds(1));

        Optional<String> secret = client.readSecret("missing", "value");

        assertTrue(secret.isEmpty());
    }

    @Test
    void shouldFailOnServerErrors() {
        server.createContext("/v1/secret/data/broken", exchange -> writeJson(exchange, 500, "{}"));

        OpenBaoClient client = new OpenBaoClient(baseUri, "secret", "token", null,
                Duration.ofSeconds(1), Duration.ofSeconds(1));

        assertThrows(IllegalStateException.class, () -> client.readSecret("broken", "value"));
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
