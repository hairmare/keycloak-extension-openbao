package io.github.hairmare.keycloak.extension.openbao.runtime;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Iterator;
import java.util.Optional;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

class OpenBaoClient {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final HttpClient httpClient;
    private final URI baseUri;
    private final String mountPath;
    private final String token;
    private final String namespace;
    private final Duration readTimeout;

    OpenBaoClient(URI baseUri, String mountPath, String token, String namespace, Duration connectTimeout, Duration readTimeout) {
        this(baseUri, mountPath, token, namespace, connectTimeout, readTimeout, null, false);
    }

    OpenBaoClient(URI baseUri, String mountPath, String token, String namespace, Duration connectTimeout, Duration readTimeout,
            SSLContext sslContext, boolean disableHostnameVerification) {
        this.baseUri = normalizeBaseUri(baseUri);
        this.mountPath = mountPath;
        this.token = token;
        this.namespace = namespace;
        this.readTimeout = readTimeout;
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(connectTimeout);

        if (sslContext != null) {
            builder.sslContext(sslContext);
        }

        if (disableHostnameVerification) {
            SSLParameters sslParameters = new SSLParameters();
            sslParameters.setEndpointIdentificationAlgorithm(null);
            builder.sslParameters(sslParameters);
        }

        this.httpClient = builder.build();
    }

    Optional<String> readSecret(String resolvedPath, String preferredField) {
        URI uri = buildReadUri(resolvedPath);

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(uri)
                .header("Accept", "application/json")
                .header("X-Vault-Token", token)
                .timeout(readTimeout)
                .GET();

        if (namespace != null && !namespace.isBlank()) {
            requestBuilder.header("X-Vault-Namespace", namespace);
        }

        HttpResponse<String> response;
        try {
            response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException("Unable to communicate with OpenBao", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while communicating with OpenBao", e);
        }

        if (response.statusCode() == 404) {
            return Optional.empty();
        }

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("OpenBao returned non-success status " + response.statusCode());
        }

        return extractSecretValue(response.body(), preferredField, resolvedPath);
    }

    private URI buildReadUri(String resolvedPath) {
        String mountPart = encodePathSegments(mountPath);
        String secretPart = encodePathSegments(resolvedPath);
        return baseUri.resolve("/v1/" + mountPart + "/data/" + secretPart);
    }

    private Optional<String> extractSecretValue(String responseBody, String preferredField, String resolvedPath) {
        final JsonNode root;
        try {
            root = OBJECT_MAPPER.readTree(responseBody);
        } catch (IOException e) {
            throw new IllegalStateException("OpenBao returned invalid JSON", e);
        }

        JsonNode dataNode = root.path("data").path("data");
        if (!dataNode.isObject()) {
            return Optional.empty();
        }

        if (preferredField != null && !preferredField.isBlank()) {
            Optional<String> preferred = nodeToString(dataNode.get(preferredField));
            if (preferred.isPresent()) {
                return preferred;
            }
        }

        String leafKey = resolvedPath;
        int index = resolvedPath.lastIndexOf('/');
        if (index >= 0 && index < resolvedPath.length() - 1) {
            leafKey = resolvedPath.substring(index + 1);
        }

        Optional<String> leafValue = nodeToString(dataNode.get(leafKey));
        if (leafValue.isPresent()) {
            return leafValue;
        }

        if (dataNode.size() == 1) {
            Iterator<JsonNode> elements = dataNode.elements();
            if (elements.hasNext()) {
                return nodeToString(elements.next());
            }
        }

        return Optional.empty();
    }

    private Optional<String> nodeToString(JsonNode valueNode) {
        if (valueNode == null || valueNode.isNull()) {
            return Optional.empty();
        }

        if (valueNode.isValueNode()) {
            return Optional.of(valueNode.asText());
        }

        return Optional.of(valueNode.toString());
    }

    static String encodePathSegments(String path) {
        String[] segments = path.split("/");
        StringBuilder sb = new StringBuilder();
        for (String segment : segments) {
            if (segment == null || segment.isBlank()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('/');
            }
            sb.append(URLEncoder.encode(segment, StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    private URI normalizeBaseUri(URI uri) {
        String text = uri.toString();
        if (text.endsWith("/")) {
            return uri;
        }
        return URI.create(text + "/");
    }
}
