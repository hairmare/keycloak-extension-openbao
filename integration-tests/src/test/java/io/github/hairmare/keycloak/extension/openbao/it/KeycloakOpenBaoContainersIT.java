package io.github.hairmare.keycloak.extension.openbao.it;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

@Testcontainers(disabledWithoutDocker = true)
class KeycloakOpenBaoContainersIT {

        private static final ObjectMapper JSON = new ObjectMapper();

        private static final DockerImageName OPENBAO_IMAGE = DockerImageName.parse("openbao/openbao:2.5.3");
        private static final DockerImageName KEYCLOAK_IMAGE = DockerImageName.parse("quay.io/keycloak/keycloak:26.6.1");
        private static final DockerImageName DIRECTORY_SERVER_IMAGE = DockerImageName
                        .parse("quay.io/389ds/dirsrv:latest");

        @Test
        void shouldStartKeycloakWithOpenBaoVaultProvider() throws Exception {
                Path providerJar = resolveProviderJar();

                try (Network network = Network.newNetwork();
                                GenericContainer<?> openBao = createOpenBaoContainer(network);
                                GenericContainer<?> keycloak = createKeycloakContainer(network, providerJar)) {

                        openBao.start();
                        seedSecret(openBao, "master_admin__password", "admin");

                        keycloak.start();

                        String tokenEndpoint = "http://localhost:" + keycloak.getMappedPort(8080)
                                        + "/realms/master/protocol/openid-connect/token";

                        HttpRequest tokenRequest = HttpRequest.newBuilder(URI.create(tokenEndpoint))
                                        .header("Content-Type", "application/x-www-form-urlencoded")
                                        .timeout(Duration.ofSeconds(20))
                                        .POST(HttpRequest.BodyPublishers.ofString(
                                                        "client_id=admin-cli&grant_type=password&username=admin&password=admin",
                                                        StandardCharsets.UTF_8))
                                        .build();

                        HttpResponse<String> tokenResponse = HttpClient.newHttpClient().send(tokenRequest,
                                        HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

                        String logs = keycloak.getLogs();
                        assertEquals(200, tokenResponse.statusCode(),
                                        "Expected Keycloak admin token endpoint to be reachable");
                        assertTrue(tokenResponse.body().contains("access_token"),
                                        "Expected an access token in Keycloak response");
                        assertTrue(logs.toLowerCase().contains("openbao"),
                                        "Expected Keycloak logs to include OpenBao vault configuration");
                        assertFalse(logs.contains("Invalid value for option '--vault': openbao"),
                                        "Keycloak should not reject custom OpenBao provider as a built-in --vault value");
                }
        }

        @Test
        void shouldObtainLdapBindCredentialFromVaultForUserFederation() throws Exception {
                Path providerJar = resolveProviderJar();

                try (Network network = Network.newNetwork();
                                GenericContainer<?> openBao = createOpenBaoContainer(network);
                                GenericContainer<?> directoryServer = create389dsContainer(network);
                                GenericContainer<?> keycloak = createKeycloakContainer(network, providerJar)) {

                        openBao.start();
                        directoryServer.start();
                        seedSecret(openBao, "master_admin__password", "admin");
                        seedSecret(openBao, "vaultdemo_ldapBindCredential", "admin");

                        keycloak.start();

                        String adminToken = obtainAdminAccessToken(keycloak);
                        createRealm(keycloak, adminToken, "vaultdemo");

                        String ldapComponentId = createLdapUserFederation(keycloak, adminToken, "vaultdemo");
                        HttpResponse<String> initialSync = triggerLdapSync(keycloak, adminToken, "vaultdemo",
                                        ldapComponentId);
                        assertSyncSucceeded(initialSync);

                        int versionBeforeRotation = getSecretCurrentVersion(openBao, "vaultdemo_ldapBindCredential");
                        seedSecret(openBao, "vaultdemo_ldapBindCredential", "admin");
                        int versionAfterRotation = getSecretCurrentVersion(openBao, "vaultdemo_ldapBindCredential");
                        assertTrue(versionAfterRotation > versionBeforeRotation,
                                        "Expected OpenBao secret version to increase after rotation. before="
                                                        + versionBeforeRotation + " after=" + versionAfterRotation);

                        HttpResponse<String> postRotationSync = triggerLdapSync(keycloak, adminToken, "vaultdemo",
                                        ldapComponentId);
                        assertSyncSucceeded(postRotationSync);

                        String logsAfterRecovery = keycloak.getLogs().toLowerCase();
                        assertTrue(logsAfterRecovery.contains("openbao"),
                                        "Expected OpenBao-related logs during LDAP sync flow");
                }
        }

        @Test
        void shouldObtainOidcClientSecretFromVaultForIdentityProvider() throws Exception {
                Path providerJar = resolveProviderJar();

                try (Network network = Network.newNetwork();
                                GenericContainer<?> openBao = createOpenBaoContainer(network);
                                GenericContainer<?> keycloak = createKeycloakContainer(network, providerJar)) {

                        openBao.start();
                        seedSecret(openBao, "master_admin__password", "admin");
                        seedSecret(openBao, "vaultdemo_oidcClientSecret", "super-secret-client-value");

                        keycloak.start();

                        String adminToken = obtainAdminAccessToken(keycloak);
                        createRealm(keycloak, adminToken, "vaultdemo");
                        createOidcIdentityProviderWithVaultSecret(keycloak, adminToken, "vaultdemo", "external-oidc");
                        JsonNode idp = getOidcIdentityProvider(keycloak, adminToken, "vaultdemo", "external-oidc");
                        assertEquals("external-oidc", idp.path("alias").asText());
                        assertEquals("${vault.oidcClientSecret}",
                                        idp.path("config").path("clientSecret").asText(),
                                        "Expected OIDC IdP to store a vault placeholder for client secret");

                        seedSecret(openBao, "vaultdemo_oidcClientSecret", "super-secret-client-value-rotated");

                        String logs = keycloak.getLogs().toLowerCase();
                        assertTrue(logs.contains("openbao"),
                                        "Expected OpenBao-related log entries while configuring OIDC IdP");
                }
        }

        @SuppressWarnings("resource")
        private static GenericContainer<?> createOpenBaoContainer(Network network) {
                return new GenericContainer<>(OPENBAO_IMAGE)
                                .withNetwork(network)
                                .withNetworkAliases("openbao")
                                .withExposedPorts(8200)
                                .withCommand("server", "-dev", "-dev-root-token-id=root",
                                                "-dev-listen-address=0.0.0.0:8200")
                                .waitingFor(Wait.forHttp("/v1/sys/health").forPort(8200).forStatusCode(200));
        }

        @SuppressWarnings("resource")
        private static GenericContainer<?> createKeycloakContainer(Network network, Path providerJar) {
                return new GenericContainer<>(KEYCLOAK_IMAGE)
                                .withNetwork(network)
                                .withExposedPorts(8080)
                                .withEnv("KEYCLOAK_ADMIN", "admin")
                                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                                .withFileSystemBind(providerJar.toString(),
                                                "/opt/keycloak/providers/keycloak-extension-openbao.jar",
                                                BindMode.READ_ONLY)
                                .withCommand(
                                                "start-dev",
                                                "--http-enabled=true",
                                                "--hostname-strict=false",
                                                "--spi-vault-provider=openbao",
                                                "--spi-vault-openbao-address=http://openbao:8200",
                                                "--spi-vault-openbao-token=root",
                                                "--spi-vault-openbao-mountPath=secret",
                                                "--spi-vault-openbao-keyResolvers=REALM_UNDERSCORE_KEY",
                                                "--spi-vault-openbao-secretField=value")
                                .waitingFor(Wait.forHttp("/realms/master/.well-known/openid-configuration")
                                                .forPort(8080));
        }

        @SuppressWarnings("resource")
        private static GenericContainer<?> create389dsContainer(Network network) {
                return new GenericContainer<>(DIRECTORY_SERVER_IMAGE)
                                .withNetwork(network)
                                .withNetworkAliases("directoryserver")
                                .withExposedPorts(3389)
                                .withEnv("DS_DM_PASSWORD", "admin")
                                .withEnv("DS_SUFFIX_NAME", "dc=example,dc=org")
                                .waitingFor(Wait.forListeningPort());
        }

        private static String obtainAdminAccessToken(GenericContainer<?> keycloak)
                        throws IOException, InterruptedException {
                String tokenEndpoint = "http://localhost:" + keycloak.getMappedPort(8080)
                                + "/realms/master/protocol/openid-connect/token";

                HttpRequest tokenRequest = HttpRequest.newBuilder(URI.create(tokenEndpoint))
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .timeout(Duration.ofSeconds(20))
                                .POST(HttpRequest.BodyPublishers.ofString(
                                                "client_id=admin-cli&grant_type=password&username=admin&password=admin",
                                                StandardCharsets.UTF_8))
                                .build();

                HttpResponse<String> tokenResponse = HttpClient.newHttpClient().send(tokenRequest,
                                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                assertEquals(200, tokenResponse.statusCode(), "Expected successful admin token request");

                JsonNode tokenPayload = parseJson(tokenResponse.body(), "admin token response");
                String token = tokenPayload.path("access_token").asText();
                if (token == null || token.isBlank()) {
                        throw new IllegalStateException("Access token missing in response: " + tokenResponse.body());
                }
                return token;
        }

        private static void createRealm(GenericContainer<?> keycloak, String adminToken, String realm)
                        throws IOException, InterruptedException {
                ObjectNode payload = JSON.createObjectNode();
                payload.put("realm", realm);
                payload.put("enabled", true);

                HttpResponse<String> response = adminRequest(keycloak, adminToken,
                                "POST",
                                "/admin/realms",
                                payload);
                assertTrue(response.statusCode() == 201 || response.statusCode() == 409,
                                "Expected realm create status 201 or 409, got " + response.statusCode() + " body="
                                                + response.body());
        }

        private static String createLdapUserFederation(GenericContainer<?> keycloak, String adminToken, String realm)
                        throws IOException, InterruptedException {
                ObjectNode payload = JSON.createObjectNode();
                payload.put("name", "directoryserver");
                payload.put("providerId", "ldap");
                payload.put("providerType", "org.keycloak.storage.UserStorageProvider");
                payload.put("parentId", realm);

                ObjectNode config = payload.putObject("config");
                putSingleValueConfig(config, "enabled", "true");
                putSingleValueConfig(config, "priority", "0");
                putSingleValueConfig(config, "cachePolicy", "DEFAULT");
                putSingleValueConfig(config, "editMode", "READ_ONLY");
                putSingleValueConfig(config, "syncRegistrations", "false");
                putSingleValueConfig(config, "connectionUrl", "ldap://directoryserver:3389");
                putSingleValueConfig(config, "usersDn", "dc=example,dc=org");
                putSingleValueConfig(config, "bindDn", "cn=Directory Manager");
                putSingleValueConfig(config, "bindCredential", "${vault.ldapBindCredential}");
                putSingleValueConfig(config, "vendor", "other");
                putSingleValueConfig(config, "usernameLDAPAttribute", "uid");
                putSingleValueConfig(config, "rdnLDAPAttribute", "cn");
                putSingleValueConfig(config, "uuidLDAPAttribute", "entryUUID");
                putSingleValueConfig(config, "userObjectClasses", "inetOrgPerson, organizationalPerson");
                putSingleValueConfig(config, "connectionPooling", "true");
                putSingleValueConfig(config, "pagination", "true");

                HttpResponse<String> response = adminRequest(keycloak, adminToken,
                                "POST",
                                "/admin/realms/" + realm + "/components",
                                payload);
                assertEquals(201, response.statusCode(),
                                "Expected LDAP component creation to succeed: " + response.body());

                String location = response.headers().firstValue("Location")
                                .orElseThrow(() -> new IllegalStateException(
                                                "Missing Location header for LDAP component"));
                return location.substring(location.lastIndexOf('/') + 1);
        }

        private static HttpResponse<String> triggerLdapSync(GenericContainer<?> keycloak, String adminToken,
                        String realm,
                        String componentId)
                        throws IOException, InterruptedException {
                return adminRequest(keycloak, adminToken,
                                "POST",
                                "/admin/realms/" + realm + "/user-storage/" + componentId
                                                + "/sync?action=triggerFullSync",
                                null);
        }

        private static void assertSyncSucceeded(HttpResponse<String> response) {
                assertTrue(response.statusCode() == 200 || response.statusCode() == 204,
                                "Expected LDAP sync call to succeed, got " + response.statusCode() + " body="
                                                + response.body());

                if (response.body() != null && !response.body().isBlank()) {
                        JsonNode syncPayload = parseJson(response.body(), "ldap sync response");
                        if (!syncPayload.path("failed").isMissingNode()) {
                                assertEquals(0, syncPayload.path("failed").asInt(),
                                                "Expected zero failed LDAP sync entries, got body=" + response.body());
                        } else if (!syncPayload.path("status").isMissingNode()) {
                                String status = syncPayload.path("status").asText().toLowerCase();
                                assertFalse(status.contains("error") || status.contains("exception"),
                                                "Expected non-error LDAP sync status, got body=" + response.body());
                        }
                }
        }

        private static void createOidcIdentityProviderWithVaultSecret(GenericContainer<?> keycloak, String adminToken,
                        String realm, String alias) throws IOException, InterruptedException {
                ObjectNode payload = JSON.createObjectNode();
                payload.put("alias", alias);
                payload.put("providerId", "oidc");
                payload.put("enabled", true);
                payload.put("trustEmail", false);

                ObjectNode config = payload.putObject("config");
                config.put("clientId", "demo-client");
                config.put("clientSecret", "${vault.oidcClientSecret}");
                config.put("authorizationUrl", "https://idp.example.org/auth");
                config.put("tokenUrl", "https://idp.example.org/token");
                config.put("userInfoUrl", "https://idp.example.org/userinfo");

                HttpResponse<String> response = adminRequest(keycloak, adminToken,
                                "POST",
                                "/admin/realms/" + realm + "/identity-provider/instances",
                                payload);
                assertEquals(201, response.statusCode(), "Expected OIDC IdP creation to succeed: " + response.body());
        }

        private static JsonNode getOidcIdentityProvider(GenericContainer<?> keycloak, String adminToken,
                        String realm, String alias) throws IOException, InterruptedException {
                HttpResponse<String> response = adminRequest(keycloak, adminToken,
                                "GET",
                                "/admin/realms/" + realm + "/identity-provider/instances/" + alias,
                                null);
                assertEquals(200, response.statusCode(), "Expected OIDC IdP lookup to succeed: " + response.body());
                return parseJson(response.body(), "oidc identity provider response");
        }

        private static HttpResponse<String> adminRequest(GenericContainer<?> keycloak, String accessToken,
                        String method, String path, JsonNode payload) throws IOException, InterruptedException {
                String url = "http://localhost:" + keycloak.getMappedPort(8080) + path;
                HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                                .header("Authorization", "Bearer " + accessToken)
                                .timeout(Duration.ofSeconds(20));

                if ("GET".equals(method)) {
                        builder.GET();
                } else {
                        builder.header("Content-Type", "application/json");
                        builder.method(method,
                                        payload == null
                                                        ? HttpRequest.BodyPublishers.noBody()
                                                        : HttpRequest.BodyPublishers.ofString(payload.toString(),
                                                                        StandardCharsets.UTF_8));
                }

                return HttpClient.newHttpClient().send(builder.build(),
                                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        }

        private static void seedSecret(GenericContainer<?> openBao, String path, String value)
                        throws IOException, InterruptedException {
                String baseUrl = "http://localhost:" + openBao.getMappedPort(8200);
                ObjectNode payload = JSON.createObjectNode();
                payload.putObject("data").put("value", value);

                HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/v1/secret/data/" + path))
                                .header("X-Vault-Token", "root")
                                .header("Content-Type", "application/json")
                                .POST(HttpRequest.BodyPublishers.ofString(payload.toString(), StandardCharsets.UTF_8))
                                .timeout(Duration.ofSeconds(10))
                                .build();

                HttpResponse<String> response = HttpClient.newHttpClient().send(request,
                                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                if (response.statusCode() != 200 && response.statusCode() != 204) {
                        throw new IllegalStateException(
                                        "Unable to seed OpenBao secret. Status=" + response.statusCode() + ", body="
                                                        + response.body());
                }
        }

        private static int getSecretCurrentVersion(GenericContainer<?> openBao, String path)
                        throws IOException, InterruptedException {
                String baseUrl = "http://localhost:" + openBao.getMappedPort(8200);
                HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/v1/secret/metadata/" + path))
                                .header("X-Vault-Token", "root")
                                .GET()
                                .timeout(Duration.ofSeconds(10))
                                .build();

                HttpResponse<String> response = HttpClient.newHttpClient().send(request,
                                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                assertEquals(200, response.statusCode(),
                                "Expected to read OpenBao metadata for rotation verification: " + response.body());

                JsonNode metadata = parseJson(response.body(), "openbao secret metadata");
                return metadata.path("data").path("current_version").asInt(-1);
        }

        private static void putSingleValueConfig(ObjectNode config, String key, String value) {
                ArrayNode values = JSON.createArrayNode();
                values.add(value);
                config.set(key, values);
        }

        private static JsonNode parseJson(String body, String source) {
                try {
                        return JSON.readTree(body == null ? "" : body);
                } catch (IOException e) {
                        throw new IllegalStateException("Unable to parse JSON from " + source + ": " + body, e);
                }
        }

        private static Path resolveProviderJar() throws IOException {
                Path runtimeTarget = Path.of("..", "runtime", "target").normalize();
                if (!Files.isDirectory(runtimeTarget)) {
                        throw new IllegalStateException("Runtime target directory does not exist: " + runtimeTarget);
                }

                try (Stream<Path> jars = Files.list(runtimeTarget)) {
                        return jars
                                        .filter(path -> path.getFileName().toString()
                                                        .startsWith("keycloak-extension-openbao-"))
                                        .filter(path -> path.getFileName().toString().endsWith(".jar"))
                                        .filter(path -> !path.getFileName().toString().endsWith("-sources.jar"))
                                        .filter(path -> !path.getFileName().toString().endsWith("-javadoc.jar"))
                                        .max(Comparator.comparing(Path::toString))
                                        .orElseThrow(() -> new IllegalStateException(
                                                        "Could not find built runtime provider jar under "
                                                                        + runtimeTarget));
                }
        }
}
