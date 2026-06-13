/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class LegacyPBEByteEncryptorTest {

    private static final char[] PASSWORD = "geoserver".toCharArray();
    private static final byte[] MESSAGE = "secret-password".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void registerBouncyCastleProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void testPbeWithMd5AndDesCanDecryptJasyptEncryptedBytes() {
        StandardPBEByteEncryptor jasyptEncryptor = createJasyptEncryptor("PBEWITHMD5ANDDES", null);
        LegacyPBEEncryptor legacyEncryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);

        byte[] encrypted = jasyptEncryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, legacyEncryptor.decrypt(encrypted));
    }

    @Test
    void testPbeWithMd5AndDesCanBeDecryptedByJasypt() {
        StandardPBEByteEncryptor jasyptEncryptor = createJasyptEncryptor("PBEWITHMD5ANDDES", null);
        LegacyPBEEncryptor legacyEncryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);

        byte[] encrypted = legacyEncryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, jasyptEncryptor.decrypt(encrypted));
    }

    @Test
    void testPbeWithSha256And256BitAesCbcBcCanDecryptJasyptEncryptedBytes() {
        StandardPBEByteEncryptor jasyptEncryptor = createJasyptEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");
        LegacyPBEEncryptor legacyEncryptor = createLegacyEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");

        byte[] encrypted = jasyptEncryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, legacyEncryptor.decrypt(encrypted));
    }

    @Test
    void testPbeWithSha256And256BitAesCbcBcCanBeDecryptedByJasypt() {
        StandardPBEByteEncryptor jasyptEncryptor = createJasyptEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");
        LegacyPBEEncryptor legacyEncryptor = createLegacyEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");

        byte[] encrypted = legacyEncryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, jasyptEncryptor.decrypt(encrypted));
    }

    @Test
    void testStringEncryptDecrypt() {
        LegacyPBEEncryptor encryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);
        String original = "secret-password";
        String encrypted = encryptor.encrypt(original);
        assertNotNull(encrypted);
        assertEquals(original, encryptor.decrypt(encrypted));
    }

    @Test
    void testStringEncryptDecryptWithBC() {
        LegacyPBEEncryptor encryptor = createLegacyEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");
        String original = "secret-password";
        String encrypted = encryptor.encrypt(original);
        assertNotNull(encrypted);
        assertEquals(original, encryptor.decrypt(encrypted));
    }

    @Test
    void testStringEncryptDecryptEmpty() {
        LegacyPBEEncryptor encryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);
        String encrypted = encryptor.encrypt("");
        assertNotNull(encrypted);
        assertEquals("", encryptor.decrypt(encrypted));
    }

    @Test
    void testByteArrayEncryptDecryptEmpty() {
        LegacyPBEEncryptor encryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);
        byte[] encrypted = encryptor.encrypt(new byte[0]);
        assertNotNull(encrypted);
        assertArrayEquals(new byte[0], encryptor.decrypt(encrypted));
    }

    @Test
    void testStringEncryptNullReturnsNull() {
        LegacyPBEEncryptor encryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);
        assertNull(encryptor.encrypt((String) null));
        assertNull(encryptor.decrypt((String) null));
    }

    @Test
    void testByteArrayEncryptNullReturnsNull() {
        LegacyPBEEncryptor encryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);
        assertNull(encryptor.encrypt((byte[]) null));
        assertNull(encryptor.decrypt((byte[]) null));
    }

    @Test
    void testCustomSaltSize() {
        LegacyPBEEncryptor encryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);
        encryptor.setSaltSizeBytes(8);
        byte[] encrypted = encryptor.encrypt(MESSAGE);
        assertArrayEquals(MESSAGE, encryptor.decrypt(encrypted));
    }

    @Test
    void testCustomSaltSizeWithBC() {
        LegacyPBEEncryptor encryptor = createLegacyEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");
        encryptor.setSaltSizeBytes(16);
        byte[] encrypted = encryptor.encrypt(MESSAGE);
        assertArrayEquals(MESSAGE, encryptor.decrypt(encrypted));
    }

    @Test
    void testInvalidSaltSizeThrowsException() {
        LegacyPBEEncryptor encryptor = new LegacyPBEEncryptor();
        assertThrows(IllegalArgumentException.class, () -> encryptor.setSaltSizeBytes(0));
        assertThrows(IllegalArgumentException.class, () -> encryptor.setSaltSizeBytes(-1));
    }

    @Test
    void testCustomKeyObtentionIterations() {
        LegacyPBEEncryptor encryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);
        encryptor.setKeyObtentionIterations(5000);
        byte[] encrypted = encryptor.encrypt(MESSAGE);
        assertArrayEquals(MESSAGE, encryptor.decrypt(encrypted));
    }

    @Test
    void testInvalidKeyObtentionIterationsThrowsException() {
        LegacyPBEEncryptor encryptor = new LegacyPBEEncryptor();
        assertThrows(IllegalArgumentException.class, () -> encryptor.setKeyObtentionIterations(0));
        assertThrows(IllegalArgumentException.class, () -> encryptor.setKeyObtentionIterations(-1));
    }

    @Test
    void testClearPasswordChangesEncryptionKey() {
        LegacyPBEEncryptor encryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);
        byte[] encrypted = encryptor.encrypt(MESSAGE);
        encryptor.clearPassword();
        assertThrows(Exception.class, () -> encryptor.decrypt(encrypted));
    }

    @Test
    void testEncryptWithoutPasswordThrowsException() {
        LegacyPBEEncryptor encryptor = new LegacyPBEEncryptor();
        encryptor.setAlgorithm("PBEWITHMD5ANDDES");
        assertThrows(IllegalStateException.class, () -> encryptor.encrypt(MESSAGE));
    }

    @Test
    void testEncryptWithoutAlgorithmThrowsException() {
        LegacyPBEEncryptor encryptor = new LegacyPBEEncryptor();
        encryptor.setPasswordCharArray(PASSWORD);
        assertThrows(IllegalStateException.class, () -> encryptor.encrypt(MESSAGE));
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

    private static LegacyPBEEncryptor createLegacyEncryptor(String algorithm, String providerName) {
        LegacyPBEEncryptor encryptor = new LegacyPBEEncryptor();
        encryptor.setPasswordCharArray(PASSWORD);
        encryptor.setAlgorithm(algorithm);
        if (providerName != null) {
            encryptor.setProviderName(providerName);
        }
        return encryptor;
    }
}
