/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.geoserver.security.SecurityUtils;

/**
 * Minimal backward-compatible replacement for Jasypt's {@code StandardPBEByteEncryptor} and
 * {@code StandardPBEStringEncryptor} .
 */
final class LegacyPBEEncryptor {

    private static final int DEFAULT_SALT_SIZE_BYTES = 8;
    private static final int DEFAULT_KEY_OBTENTION_ITERATIONS = 1000;

    private char[] password;
    private String providerName;
    private String algorithm;
    private Integer saltSizeBytes;
    private Integer computedSaltSizeBytes;
    private int keyObtentionIterations = DEFAULT_KEY_OBTENTION_ITERATIONS;

    void setPasswordCharArray(char[] password) {
        clearPassword();
        this.password = password == null ? null : Arrays.copyOf(password, password.length);
    }

    void setProviderName(String providerName) {
        this.providerName = providerName;
        this.computedSaltSizeBytes = null;
    }

    void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
        this.computedSaltSizeBytes = null;
    }

    void setSaltSizeBytes(int saltSizeBytes) {
        if (saltSizeBytes <= 0) {
            throw new IllegalArgumentException("Salt size must be greater than zero");
        }
        this.saltSizeBytes = saltSizeBytes;
    }

    void setKeyObtentionIterations(int keyObtentionIterations) {
        if (keyObtentionIterations <= 0) {
            throw new IllegalArgumentException("Key obtention iterations must be greater than zero");
        }
        this.keyObtentionIterations = keyObtentionIterations;
    }

    String encrypt(String message) {
        if (message == null) {
            return null;
        }

        try {
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedBytes = encrypt(messageBytes);
            return java.util.Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    String decrypt(String encryptedMessage) {
        if (encryptedMessage == null) {
            return null;
        }

        try {
            byte[] encryptedBytes = java.util.Base64.getDecoder().decode(encryptedMessage);
            byte[] decryptedBytes = decrypt(encryptedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    byte[] encrypt(byte[] message) {
        if (message == null) {
            return null;
        }

        try {
            byte[] salt = generateSalt();
            byte[] encrypted = doFinal(Cipher.ENCRYPT_MODE, message, salt);
            return concat(salt, encrypted);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to encrypt message using algorithm '" + algorithm + "'", e);
        }
    }

    byte[] decrypt(byte[] encryptedMessage) {
        if (encryptedMessage == null) {
            return null;
        }

        try {
            int saltLength = getSaltSizeBytes();
            if (encryptedMessage.length <= saltLength) {
                throw new IllegalArgumentException("Encrypted message does not contain both salt and ciphertext");
            }

            byte[] salt = Arrays.copyOfRange(encryptedMessage, 0, saltLength);
            byte[] encrypted = Arrays.copyOfRange(encryptedMessage, saltLength, encryptedMessage.length);

            return doFinal(Cipher.DECRYPT_MODE, encrypted, salt);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to decrypt message using algorithm '" + algorithm + "'", e);
        }
    }

    private byte[] doFinal(int mode, byte[] input, byte[] salt) throws GeneralSecurityException {
        checkInitialized();

        PBEKeySpec keySpec = new PBEKeySpec(password);
        try {
            SecretKey key = newSecretKeyFactory().generateSecret(keySpec);
            AlgorithmParameterSpec parameterSpec = new PBEParameterSpec(salt, keyObtentionIterations);

            Cipher cipher = newCipher();
            cipher.init(mode, key, parameterSpec);

            return cipher.doFinal(input);
        } finally {
            keySpec.clearPassword();
        }
    }

    private byte[] generateSalt() throws GeneralSecurityException {
        byte[] salt = new byte[getSaltSizeBytes()];
        random().nextBytes(salt);
        return salt;
    }

    private int getSaltSizeBytes() throws GeneralSecurityException {
        if (saltSizeBytes != null) {
            return saltSizeBytes;
        }

        if (computedSaltSizeBytes == null) {
            computedSaltSizeBytes = computeSaltSizeBytes();
        }

        return computedSaltSizeBytes;
    }

    private int computeSaltSizeBytes() throws GeneralSecurityException {
        int blockSize = getAlgorithmBlockSize();
        return blockSize > 0 ? blockSize : DEFAULT_SALT_SIZE_BYTES;
    }

    private int getAlgorithmBlockSize() throws GeneralSecurityException {
        checkInitialized();
        return newCipher().getBlockSize();
    }

    private SecretKeyFactory newSecretKeyFactory() throws GeneralSecurityException {
        if (hasProviderName()) {
            return SecretKeyFactory.getInstance(algorithm, providerName);
        }
        return SecretKeyFactory.getInstance(algorithm);
    }

    private Cipher newCipher() throws GeneralSecurityException {
        if (hasProviderName()) {
            return Cipher.getInstance(algorithm, providerName);
        }
        return Cipher.getInstance(algorithm);
    }

    private void checkInitialized() {
        if (password == null) {
            throw new IllegalStateException("Password has not been configured");
        }
        if (isBlank(algorithm)) {
            throw new IllegalStateException("Algorithm has not been configured");
        }
    }

    private boolean hasProviderName() {
        return !isBlank(providerName);
    }

    void clearPassword() {
        if (password != null) {
            SecurityUtils.scramble(password);
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isEmpty();
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] output = new byte[first.length + second.length];
        System.arraycopy(first, 0, output, 0, first.length);
        System.arraycopy(second, 0, output, first.length, second.length);
        return output;
    }

    private static SecureRandom random() {
        return SecureRandomHolder.INSTANCE;
    }

    private static final class SecureRandomHolder {
        private static final SecureRandom INSTANCE = new SecureRandom();
    }
}
