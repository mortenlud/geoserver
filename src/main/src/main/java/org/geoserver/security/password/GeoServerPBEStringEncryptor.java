/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import java.nio.charset.StandardCharsets;

/**
 * Drop-in replacement for Jasypt's {@code StandardPBEStringEncryptor}.
 *
 * <p>Produces ciphertext in the same wire format (random salt prepended to raw ciphertext, no framing headers),
 * ensuring full backward compatibility with passwords encrypted by earlier versions of GeoServer that used Jasypt
 * directly.
 */
public final class GeoServerPBEStringEncryptor {
    private final GeoServerPBEByteEncryptor byteEncryptor = new GeoServerPBEByteEncryptor();

    public String encrypt(String message) {
        if (message == null) {
            return null;
        }

        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = byteEncryptor.encrypt(messageBytes);
        return java.util.Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedMessage) {
        if (encryptedMessage == null) {
            return null;
        }

        byte[] encryptedBytes = java.util.Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = byteEncryptor.decrypt(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
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

    public void setSaltSizeBytes(int saltSizeBytes) {
        byteEncryptor.setSaltSizeBytes(saltSizeBytes);
    }

    public void setKeyObtentionIterations(int keyObtentionIterations) {
        byteEncryptor.setKeyObtentionIterations(keyObtentionIterations);
    }

    public void clearPassword() {
        byteEncryptor.clearPassword();
    }
}
