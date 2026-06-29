package org.geoserver.security.password;

import java.nio.charset.StandardCharsets;

public final class GeoServerPBEStringEncryptor {
    private final GeoServerPBEByteEncryptor byteEncryptor = new GeoServerPBEByteEncryptor();

    public String encrypt(String message) {
        if (message == null) {
            return null;
        }

        try {
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedBytes = byteEncryptor.encrypt(messageBytes);
            return java.util.Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String decrypt(String encryptedMessage) {
        if (encryptedMessage == null) {
            return null;
        }

        try {
            byte[] encryptedBytes = java.util.Base64.getDecoder().decode(encryptedMessage);
            byte[] decryptedBytes = byteEncryptor.decrypt(encryptedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    public void setPasswordCharArray(char[] password) {
        byteEncryptor.setPasswordCharArray(password);
    }

    public void setAlgorithm(String algorithm) {
        byteEncryptor.setAlgorithm(algorithm);
    }

    public void setProviderName(String providerName) {
        byteEncryptor.setProviderName(providerName);
    }
}
