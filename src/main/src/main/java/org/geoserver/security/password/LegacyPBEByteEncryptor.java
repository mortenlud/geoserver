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
    private Integer computedSaltSizeBytes;
    private int keyObtentionIterations = DEFAULT_KEY_OBTENTION_ITERATIONS;

    void setPasswordCharArray(char[] password) {
        if (this.password != null) {
            Arrays.fill(this.password, '\0');
        }
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

    byte[] encrypt(byte[] message) {
        if (message == null) {
            return null;
        }

        try {
            byte[] salt = new byte[getSaltSizeBytes()];
            RANDOM.nextBytes(salt);

            byte[] encrypted = doFinal(Cipher.ENCRYPT_MODE, message, salt);
            return concat(salt, encrypted);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(
                    "Unable to encrypt message using algorithm '" + algorithm + "' ", e);
        }
    }

    byte[] decrypt(byte[] encryptedMessage) {
        if (encryptedMessage == null) {
            return null;
        }

        try {
            int effectiveSaltSizeBytes = getSaltSizeBytes();
            if (encryptedMessage.length <= effectiveSaltSizeBytes) {
                throw new IllegalArgumentException("Encrypted message does not contain both salt and ciphertext");
            }

            byte[] salt = Arrays.copyOfRange(encryptedMessage, 0, effectiveSaltSizeBytes);
            byte[] encrypted = Arrays.copyOfRange(encryptedMessage, effectiveSaltSizeBytes, encryptedMessage.length);

            return doFinal(Cipher.DECRYPT_MODE, encrypted, salt);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(
                    "Unable to decrypt message using algorithm '" + algorithm + "' ", e);
        }
    }

    private byte[] doFinal(int mode, byte[] input, byte[] salt) throws GeneralSecurityException {
        checkInitialized();

        PBEKeySpec keySpec = new PBEKeySpec(password);
        try {
            SecretKeyFactory keyFactory = newSecretKeyFactory();
            SecretKey key = keyFactory.generateSecret(keySpec);

            AlgorithmParameterSpec parameterSpec = new PBEParameterSpec(salt, keyObtentionIterations);

            Cipher cipher = newCipher();
            cipher.init(mode, key, parameterSpec);

            return cipher.doFinal(input);
        } finally {
            keySpec.clearPassword();
        }
    }

    private int getSaltSizeBytes() throws GeneralSecurityException {
        if (saltSizeBytes != null) {
            return saltSizeBytes;
        }

        if (computedSaltSizeBytes == null) {
            int algorithmBlockSize = getAlgorithmBlockSize();
            computedSaltSizeBytes = algorithmBlockSize > 0 ? algorithmBlockSize : DEFAULT_SALT_SIZE_BYTES;
        }

        return computedSaltSizeBytes;
    }

    private int getAlgorithmBlockSize() throws GeneralSecurityException {
        checkInitialized();
        return newCipher().getBlockSize();
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