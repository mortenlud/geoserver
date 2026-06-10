/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Minimal backward-compatible replacement for Jasypt's {@code StandardPBEByteEncryptor}.
 */
final class LegacyPBEByteEncryptor {

    private static final int DEFAULT_SALT_SIZE_BYTES = 8;
    private static final int DEFAULT_KEY_OBTENTION_ITERATIONS = 1000;

    private static final SecureRandom RANDOM = new SecureRandom();

    private char[] password;
    private String providerName;
    private String algorithm;
    private Integer saltSizeBytes;
    private int keyObtentionIterations = DEFAULT_KEY_OBTENTION_ITERATIONS;

    void setPasswordCharArray(char[] password) {
        this.password = password == null ? null : Arrays.copyOf(password, password.length);
    }

    void setProviderName(String providerName) {
        this.providerName = providerName;
    }

    void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
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

    byte[] encrypt(byte[] message) {
        if (message == null) {
            return null;
        }

        byte[] salt = new byte[getSaltSizeBytes()];
        RANDOM.nextBytes(salt);

        byte[] encrypted = doFinal(Cipher.ENCRYPT_MODE, message, salt);
        return concat(salt, encrypted);
    }

    byte[] decrypt(byte[] encryptedMessage) {
        if (encryptedMessage == null) {
            return null;
        }

        int effectiveSaltSizeBytes = getSaltSizeBytes();
        if (encryptedMessage.length <= effectiveSaltSizeBytes) {
            throw new IllegalArgumentException("Encrypted message is shorter than the configured salt size");
        }

        byte[] salt = Arrays.copyOfRange(encryptedMessage, 0, effectiveSaltSizeBytes);
        byte[] encrypted = Arrays.copyOfRange(encryptedMessage, effectiveSaltSizeBytes, encryptedMessage.length);

        return doFinal(Cipher.DECRYPT_MODE, encrypted, salt);
    }

    private byte[] doFinal(int mode, byte[] input, byte[] salt) {
        checkInitialized();

        try {
            PBEKeySpec keySpec = new PBEKeySpec(password);
            SecretKeyFactory keyFactory = newSecretKeyFactory();
            SecretKey key = keyFactory.generateSecret(keySpec);

            AlgorithmParameterSpec parameterSpec = new PBEParameterSpec(salt, keyObtentionIterations);

            Cipher cipher = newCipher();
            cipher.init(mode, key, parameterSpec);

            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to process PBE message using algorithm: " + algorithm, e);
        }
    }

    private int getSaltSizeBytes() {
        if (saltSizeBytes != null) {
            return saltSizeBytes;
        }

        int algorithmBlockSize = getAlgorithmBlockSize();
        if (algorithmBlockSize > 0) {
            return algorithmBlockSize;
        }

        return DEFAULT_SALT_SIZE_BYTES;
    }

    private int getAlgorithmBlockSize() {
        checkInitialized();

        try {
            return newCipher().getBlockSize();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to determine block size for algorithm: " + algorithm, e);
        }
    }

    private SecretKeyFactory newSecretKeyFactory() throws GeneralSecurityException {
        if (providerName != null && !providerName.isEmpty()) {
            return SecretKeyFactory.getInstance(algorithm, providerName);
        }
        return SecretKeyFactory.getInstance(algorithm);
    }

    private Cipher newCipher() throws GeneralSecurityException {
        if (providerName != null && !providerName.isEmpty()) {
            return Cipher.getInstance(algorithm, providerName);
        }
        return Cipher.getInstance(algorithm);
    }

    private void checkInitialized() {
        if (password == null) {
            throw new IllegalStateException("Password has not been configured");
        }
        if (algorithm == null || algorithm.isEmpty()) {
            throw new IllegalStateException("Algorithm has not been configured");
        }
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] output = new byte[first.length + second.length];
        System.arraycopy(first, 0, output, 0, first.length);
        System.arraycopy(second, 0, output, first.length, second.length);
        return output;
    }
}