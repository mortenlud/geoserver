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
import org.geoserver.security.SecurityUtils;

/**
 * Drop-in replacement for Jasypt's {@code StandardPBEByteEncryptor}.
 *
 * <p>Produces ciphertext in the same wire format (random salt prepended to raw ciphertext, no framing headers),
 * ensuring full backward compatibility with passwords encrypted by earlier versions of GeoServer that used Jasypt
 * directly.
 *
 * <p>Supports any PBE algorithm available through the JCA providers (e.g. {@code PBEWithMD5AndDES},
 * {@code PBEWITHSHA256AND256BITAES-CBC-BC} with Bouncy Castle). Salt size is auto-computed from the algorithm's block
 * size by default.
 */
public final class GeoServerPBEByteEncryptor {
    public static final String ALGORITHM_MD5_DES = "PBEWithMD5AndDES";

    private static final int DEFAULT_SALT_SIZE_BYTES = 8;
    private static final int DEFAULT_KEY_OBTENTION_ITERATIONS = 1000;

    private static SecureRandom random() {
        return SecureRandomHolder.INSTANCE;
    }

    private static final class SecureRandomHolder {
        private static final SecureRandom INSTANCE = new SecureRandom();
    }

    private char[] password;
    private String providerName;
    private String algorithm = ALGORITHM_MD5_DES;
    private Integer saltSizeBytes;
    private int keyObtentionIterations = DEFAULT_KEY_OBTENTION_ITERATIONS;

    private volatile Integer cachedBlockSize;

    public void setPasswordCharArray(char[] password) {
        clearPassword();
        this.password = password == null ? null : Arrays.copyOf(password, password.length);
    }

    public void setProviderName(String providerName) {
        this.providerName = providerName;
        this.cachedBlockSize = null;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
        this.cachedBlockSize = null;
    }

    public void setSaltSizeBytes(int saltSizeBytes) {
        if (saltSizeBytes <= 0) {
            throw new IllegalArgumentException("Salt size must be greater than zero");
        }
        this.saltSizeBytes = saltSizeBytes;
    }

    public void setKeyObtentionIterations(int keyObtentionIterations) {
        if (keyObtentionIterations <= 0) {
            throw new IllegalArgumentException("Key obtention iterations must be greater than zero");
        }
        this.keyObtentionIterations = keyObtentionIterations;
    }

    public byte[] encrypt(byte[] message) {
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

    public byte[] decrypt(byte[] encryptedMessage) {
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

    private byte[] generateSalt() throws GeneralSecurityException {
        byte[] salt = new byte[getSaltSizeBytes()];
        random().nextBytes(salt);
        return salt;
    }

    private int getSaltSizeBytes() throws GeneralSecurityException {
        if (saltSizeBytes != null) {
            return saltSizeBytes;
        }
        if (cachedBlockSize == null) {
            checkInitialized();
            cachedBlockSize = newCipher().getBlockSize();
        }
        return cachedBlockSize > 0 ? cachedBlockSize : DEFAULT_SALT_SIZE_BYTES;
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

    public void clearPassword() {
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
}
