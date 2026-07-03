/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class GeoServerPBEStringEncryptorTest {

    private static final char[] PASSWORD = "geoserver".toCharArray();
    private static final String ORIGINAL = "secret-password-cafe\u0301";
    private static final String ALGORITHM_MD5_DES = "PBEWITHMD5ANDDES";
    private static final String ALGORITHM_SHA256_AES = "PBEWITHSHA256AND256BITAES-CBC-BC";
    private static final String PROVIDER_BC = "BC";

    @BeforeAll
    static void registerBouncyCastleProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void testEncryptDecryptMd5Des() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        String encrypted = encryptor.encrypt(ORIGINAL);
        assertNotNull(encrypted);
        assertEquals(ORIGINAL, encryptor.decrypt(encrypted));
    }

    @Test
    void testEncryptDecryptSha256() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_SHA256_AES, PROVIDER_BC);
        String encrypted = encryptor.encrypt(ORIGINAL);
        assertNotNull(encrypted);
        assertEquals(ORIGINAL, encryptor.decrypt(encrypted));
    }

    @Test
    void testJasyptEncryptedMd5DesCanBeDecrypted() {
        StandardPBEStringEncryptor jasyptEncryptor = createJasyptEncryptor(ALGORITHM_MD5_DES, null);
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);

        String encrypted = jasyptEncryptor.encrypt(ORIGINAL);

        assertEquals(ORIGINAL, encryptor.decrypt(encrypted));
    }

    @Test
    void testGeoServerEncryptedMd5DesCanBeDecryptedByJasypt() {
        StandardPBEStringEncryptor jasyptEncryptor = createJasyptEncryptor(ALGORITHM_MD5_DES, null);
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);

        String encrypted = encryptor.encrypt(ORIGINAL);

        assertEquals(ORIGINAL, jasyptEncryptor.decrypt(encrypted));
    }

    @Test
    void testJasyptEncryptedSha256CanBeDecrypted() {
        StandardPBEStringEncryptor jasyptEncryptor = createJasyptEncryptor(ALGORITHM_SHA256_AES, PROVIDER_BC);
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_SHA256_AES, PROVIDER_BC);

        String encrypted = jasyptEncryptor.encrypt(ORIGINAL);

        assertEquals(ORIGINAL, encryptor.decrypt(encrypted));
    }

    @Test
    void testGeoServerEncryptedSha256CanBeDecryptedByJasypt() {
        StandardPBEStringEncryptor jasyptEncryptor = createJasyptEncryptor(ALGORITHM_SHA256_AES, PROVIDER_BC);
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_SHA256_AES, PROVIDER_BC);

        String encrypted = encryptor.encrypt(ORIGINAL);

        assertEquals(ORIGINAL, jasyptEncryptor.decrypt(encrypted));
    }

    @Test
    void testEncryptDecryptEmptyString() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        String encrypted = encryptor.encrypt("");
        assertNotNull(encrypted);
        assertEquals("", encryptor.decrypt(encrypted));
    }

    @Test
    void testEncryptNullReturnsNull() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        assertNull(encryptor.encrypt((String) null));
        assertNull(encryptor.decrypt((String) null));
    }

    @Test
    void testDecryptInvalidBase64ThrowsException() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        assertThrows(RuntimeException.class, () -> encryptor.decrypt("!!not-base64!!"));
    }

    @Test
    void testDecryptTruncatedStringThrowsException() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        // valid Base64 but decodes to fewer bytes than the salt size requires
        String tooShort = "AAA=";
        Exception ex = assertThrows(RuntimeException.class, () -> encryptor.decrypt(tooShort));
        assertTrue(
                ex.getMessage().contains("Encrypted message does not contain both salt and ciphertext"),
                "Expected ´Decryption failed´ was: " + ex.getMessage());
    }

    @Test
    void testEncryptWithoutPasswordThrowsException() {
        GeoServerPBEStringEncryptor encryptor = new GeoServerPBEStringEncryptor();
        encryptor.setAlgorithm(ALGORITHM_MD5_DES);
        assertThrows(RuntimeException.class, () -> encryptor.encrypt(ORIGINAL));
    }

    @Test
    void testCustomSaltSize() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_SHA256_AES, PROVIDER_BC);
        encryptor.setSaltSizeBytes(16);
        String encrypted = encryptor.encrypt(ORIGINAL);
        assertEquals(ORIGINAL, encryptor.decrypt(encrypted));
    }

    @Test
    void testInvalidSaltSizeThrowsException() {
        GeoServerPBEStringEncryptor encryptor = new GeoServerPBEStringEncryptor();
        assertThrows(IllegalArgumentException.class, () -> encryptor.setSaltSizeBytes(0));
        assertThrows(IllegalArgumentException.class, () -> encryptor.setSaltSizeBytes(-1));
    }

    @Test
    void testCustomKeyObtentionIterations() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        encryptor.setKeyObtentionIterations(5000);
        String encrypted = encryptor.encrypt(ORIGINAL);
        assertEquals(ORIGINAL, encryptor.decrypt(encrypted));
    }

    @Test
    void testInvalidKeyObtentionIterationsThrowsException() {
        GeoServerPBEStringEncryptor encryptor = new GeoServerPBEStringEncryptor();
        assertThrows(IllegalArgumentException.class, () -> encryptor.setKeyObtentionIterations(0));
        assertThrows(IllegalArgumentException.class, () -> encryptor.setKeyObtentionIterations(-1));
    }

    @Test
    void testClearPasswordPreventsDecryption() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        String encrypted = encryptor.encrypt(ORIGINAL);
        encryptor.clearPassword();
        assertThrows(RuntimeException.class, () -> encryptor.decrypt(encrypted));
    }

    @Test
    void testSetPasswordAfterClearWorks() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        String encrypted = encryptor.encrypt(ORIGINAL);
        encryptor.clearPassword();
        encryptor.setPasswordCharArray(PASSWORD);
        String encrypted2 = encryptor.encrypt(ORIGINAL);
        assertEquals(ORIGINAL, encryptor.decrypt(encrypted2));
    }

    @Test
    void testResetPasswordChangesEncryption() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        String encrypted = encryptor.encrypt(ORIGINAL);
        encryptor.setPasswordCharArray("different".toCharArray());
        assertThrows(RuntimeException.class, () -> encryptor.decrypt(encrypted));
    }

    @Test
    void testDifferentKeyObtentionIterationsProduceDifferentCiphertext() {
        GeoServerPBEStringEncryptor encryptor1000 = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        GeoServerPBEStringEncryptor encryptor5000 = createGeoServerEncryptor(ALGORITHM_MD5_DES, null);
        encryptor5000.setKeyObtentionIterations(5000);

        String encrypted1000 = encryptor1000.encrypt(ORIGINAL);
        String encrypted5000 = encryptor5000.encrypt(ORIGINAL);

        assertNotEquals(encrypted1000, encrypted5000, "ciphertexts with different iteration counts should differ");
    }

    private static StandardPBEStringEncryptor createJasyptEncryptor(String algorithm, String providerName) {
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setPasswordCharArray(PASSWORD);
        encryptor.setAlgorithm(algorithm);
        if (providerName != null) {
            encryptor.setProviderName(providerName);
        }
        encryptor.initialize();
        return encryptor;
    }

    private static GeoServerPBEStringEncryptor createGeoServerEncryptor(String algorithm, String providerName) {
        GeoServerPBEStringEncryptor encryptor = new GeoServerPBEStringEncryptor();
        encryptor.setPasswordCharArray(PASSWORD);
        encryptor.setAlgorithm(algorithm);
        if (providerName != null) {
            encryptor.setProviderName(providerName);
        }
        return encryptor;
    }
}
