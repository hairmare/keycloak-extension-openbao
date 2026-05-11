package io.github.hairmare.keycloak.extension.openbao.runtime;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

import org.keycloak.vault.VaultRawSecret;

final class ByteArrayVaultRawSecret implements VaultRawSecret {

    private byte[] value;
    private final boolean present;

    private ByteArrayVaultRawSecret(byte[] value, boolean present) {
        this.value = value;
        this.present = present;
    }

    static ByteArrayVaultRawSecret empty() {
        return new ByteArrayVaultRawSecret(null, false);
    }

    static ByteArrayVaultRawSecret fromString(String value) {
        return new ByteArrayVaultRawSecret(value.getBytes(StandardCharsets.UTF_8), true);
    }

    @Override
    public Optional<ByteBuffer> get() {
        if (!present || value == null) {
            return Optional.empty();
        }
        return Optional.of(ByteBuffer.wrap(Arrays.copyOf(value, value.length)));
    }

    @Override
    public Optional<byte[]> getAsArray() {
        if (!present || value == null) {
            return Optional.empty();
        }
        return Optional.of(Arrays.copyOf(value, value.length));
    }

    @Override
    public void close() {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
            value = null;
        }
    }
}
