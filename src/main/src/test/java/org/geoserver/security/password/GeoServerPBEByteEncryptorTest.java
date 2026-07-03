/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.junit.BeforeClass;
import org.junit.Test;

public class GeoServerPBEByteEncryptorTest {

    private static final char[] PASSWORD = "geoserver".toCharArray();
    private static final byte[] MESSAGE = "secret-password-cafe\u0301".getBytes(StandardCharsets.UTF_8);
    private static final String ALGORITHM_MD5_DES = "PBEWITHMD5ANDDES";
    private static final String ALGORITHM_SHA256_AES = "PBEWITHSHA256AND256BITAES-CBC-BC";
    private static final String PROVIDER_BC = "BC";

    @BeforeClass
    public static void registerBouncyCastleProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void testJasyptEncryptedMd5DesCanBeDecrypted() {
        StandardPBEByteEncryptor jasyptEncryptor = createJasyptEncryptor(ALGORITHM_MD5_DES, null);
        GeoServerPBEByteEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);

        byte[] encrypted = jasyptEncryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, encryptor.decrypt(encrypted));
    }

    @Test
    public void testGeoServerEncryptedMd5DesCanBeDecryptedByJasypt() {
        StandardPBEByteEncryptor jasyptEncryptor = createJasyptEncryptor(ALGORITHM_MD5_DES, null);
        GeoServerPBEByteEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);

        byte[] encrypted = encryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, jasyptEncryptor.decrypt(encrypted));
    }

    @Test
    public void testJasyptEncryptedSha256CanBeDecrypted() {
        StandardPBEByteEncryptor jasyptEncryptor = createJasyptEncryptor(ALGORITHM_SHA256_AES, PROVIDER_BC);
        GeoServerPBEByteEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_SHA256_AES, PROVIDER_BC);

        byte[] encrypted = jasyptEncryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, encryptor.decrypt(encrypted));
    }

    @Test
    public void testGeoServerEncryptedSha256CanBeDecryptedByJasypt() {
        StandardPBEByteEncryptor jasyptEncryptor = createJasyptEncryptor(ALGORITHM_SHA256_AES, PROVIDER_BC);
        GeoServerPBEByteEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_SHA256_AES, PROVIDER_BC);

        byte[] encrypted = encryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, jasyptEncryptor.decrypt(encrypted));
    }

    @Test
    public void testEncryptDecryptEmptyArray() {
        GeoServerPBEByteEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        byte[] encrypted = encryptor.encrypt(new byte[0]);
        assertNotNull(encrypted);
        assertArrayEquals(new byte[0], encryptor.decrypt(encrypted));
    }

    @Test
    public void testEncryptNullReturnsNull() {
        GeoServerPBEByteEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        assertNull(encryptor.encrypt((byte[]) null));
        assertNull(encryptor.decrypt((byte[]) null));
    }

    @Test
    public void testDecryptTruncatedDataThrowsException() {
        GeoServerPBEByteEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        byte[] tooShort = new byte[3];
        assertThrows(IllegalArgumentException.class, () -> encryptor.decrypt(tooShort));
    }

    @Test
    public void testCustomSaltSize() {
        GeoServerPBEByteEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_SHA256_AES, PROVIDER_BC);
        encryptor.setSaltSizeBytes(16);
        byte[] encrypted = encryptor.encrypt(MESSAGE);
        assertArrayEquals(MESSAGE, encryptor.decrypt(encrypted));
    }

    @Test
    public void testInvalidSaltSizeThrowsException() {
        GeoServerPBEByteEncryptor encryptor = new GeoServerPBEByteEncryptor();
        assertThrows(IllegalArgumentException.class, () -> encryptor.setSaltSizeBytes(0));
        assertThrows(IllegalArgumentException.class, () -> encryptor.setSaltSizeBytes(-1));
    }

    @Test
    public void testCustomKeyObtentionIterations() {
        GeoServerPBEByteEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        encryptor.setKeyObtentionIterations(5000);
        byte[] encrypted = encryptor.encrypt(MESSAGE);
        assertArrayEquals(MESSAGE, encryptor.decrypt(encrypted));
    }

    @Test
    public void testInvalidKeyObtentionIterationsThrowsException() {
        GeoServerPBEByteEncryptor encryptor = new GeoServerPBEByteEncryptor();
        assertThrows(IllegalArgumentException.class, () -> encryptor.setKeyObtentionIterations(0));
        assertThrows(IllegalArgumentException.class, () -> encryptor.setKeyObtentionIterations(-1));
    }

    @Test
    public void testClearPasswordPreventsDecryption() {
        GeoServerPBEByteEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        byte[] encrypted = encryptor.encrypt(MESSAGE);
        encryptor.clearPassword();
        assertThrows(IllegalStateException.class, () -> encryptor.decrypt(encrypted));
    }

    @Test
    public void testSetPasswordAfterClearWorks() {
        GeoServerPBEByteEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        byte[] encrypted = encryptor.encrypt(MESSAGE);
        encryptor.clearPassword();
        // re-set password and confirm re-encrypt works
        encryptor.setPasswordCharArray(PASSWORD);
        byte[] encrypted2 = encryptor.encrypt(MESSAGE);
        assertArrayEquals(MESSAGE, encryptor.decrypt(encrypted2));
    }

    @Test
    public void testResetPasswordChangesEncryptionKey() {
        GeoServerPBEByteEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        byte[] encrypted = encryptor.encrypt(MESSAGE);
        // set a different password ? old ciphertext should not decrypt
        encryptor.setPasswordCharArray("different".toCharArray());
        assertThrows(IllegalStateException.class, () -> encryptor.decrypt(encrypted));
    }

    @Test
    public void testEncryptWithoutPasswordThrowsException() {
        GeoServerPBEByteEncryptor encryptor = new GeoServerPBEByteEncryptor();
        encryptor.setAlgorithm(ALGORITHM_MD5_DES);
        assertThrows(IllegalStateException.class, () -> encryptor.encrypt(MESSAGE));
    }

    @Test
    public void testNonExistentProviderThrowsException() {
        GeoServerPBEByteEncryptor encryptor = new GeoServerPBEByteEncryptor();
        encryptor.setPasswordCharArray(PASSWORD);
        encryptor.setAlgorithm(ALGORITHM_MD5_DES);
        encryptor.setProviderName("NonExistentProvider");
        assertThrows(IllegalStateException.class, () -> encryptor.encrypt(MESSAGE));
    }

    @Test
    public void testDifferentKeyObtentionIterationsProduceDifferentCiphertext() {
        GeoServerPBEByteEncryptor encryptor1000 = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        GeoServerPBEByteEncryptor encryptor5000 = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        encryptor5000.setKeyObtentionIterations(5000);

        byte[] encrypted1000 = encryptor1000.encrypt(MESSAGE);
        byte[] encrypted5000 = encryptor5000.encrypt(MESSAGE);

        assertNotNull(encrypted1000);
        assertNotNull(encrypted5000);
        // two ciphertexts should differ due to different iteration counts
        boolean same = true;
        for (int i = 0; i < Math.min(encrypted1000.length, encrypted5000.length); i++) {
            if (encrypted1000[i] != encrypted5000[i]) {
                same = false;
                break;
            }
        }
        assertTrue("ciphertexts with different iteration counts should differ", !same);
    }

    private static StandardPBEByteEncryptor createJasyptEncryptor(String algorithm, String providerName) {
        StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();
        encryptor.setPasswordCharArray(PASSWORD);
        encryptor.setAlgorithm(algorithm);
        if (providerName != null) {
            encryptor.setProviderName(providerName);
        }
        encryptor.initialize();
        return encryptor;
    }

    private static GeoServerPBEByteEncryptor createGeoServerEncryptor(String algorithm, String providerName) {
        GeoServerPBEByteEncryptor encryptor = new GeoServerPBEByteEncryptor();
        encryptor.setPasswordCharArray(PASSWORD);
        encryptor.setAlgorithm(algorithm);
        if (providerName != null) {
            encryptor.setProviderName(providerName);
        }
        return encryptor;
    }
}
