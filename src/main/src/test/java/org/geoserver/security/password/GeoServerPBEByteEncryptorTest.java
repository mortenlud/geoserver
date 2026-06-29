/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class GeoServerPBEByteEncryptorTest {

    private static final char[] PASSWORD = "geoserver".toCharArray();
    private static final byte[] MESSAGE = "secret-password-cafe\u0301".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void registerBouncyCastleProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void testPbeWithMd5AndDesCanDecryptJasyptEncryptedBytes() {
        StandardPBEByteEncryptor jasyptEncryptor = createJasyptEncryptor("PBEWITHMD5ANDDES", null);
        GeoServerPBEByteEncryptor legacyEncryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);

        byte[] encrypted = jasyptEncryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, legacyEncryptor.decrypt(encrypted));
    }

    @Test
    void testPbeWithMd5AndDesCanBeDecryptedByJasypt() {
        StandardPBEByteEncryptor jasyptEncryptor = createJasyptEncryptor("PBEWITHMD5ANDDES", null);
        GeoServerPBEByteEncryptor legacyEncryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);

        byte[] encrypted = legacyEncryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, jasyptEncryptor.decrypt(encrypted));
    }

    @Test
    void testPbeWithSha256And256BitAesCbcBcCanDecryptJasyptEncryptedBytes() {
        StandardPBEByteEncryptor jasyptEncryptor = createJasyptEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");
        GeoServerPBEByteEncryptor legacyEncryptor = createLegacyEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");

        byte[] encrypted = jasyptEncryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, legacyEncryptor.decrypt(encrypted));
    }

    @Test
    void testPbeWithSha256And256BitAesCbcBcCanBeDecryptedByJasypt() {
        StandardPBEByteEncryptor jasyptEncryptor = createJasyptEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");
        GeoServerPBEByteEncryptor legacyEncryptor = createLegacyEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");

        byte[] encrypted = legacyEncryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, jasyptEncryptor.decrypt(encrypted));
    }

    @Test
    void testByteArrayEncryptDecryptEmpty() {
        GeoServerPBEByteEncryptor encryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);
        byte[] encrypted = encryptor.encrypt(new byte[0]);
        assertNotNull(encrypted);
        assertArrayEquals(new byte[0], encryptor.decrypt(encrypted));
    }

    @Test
    void testByteArrayEncryptNullReturnsNull() {
        GeoServerPBEByteEncryptor encryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);
        assertNull(encryptor.encrypt((byte[]) null));
        assertNull(encryptor.decrypt((byte[]) null));
    }

    @Test
    void testCustomSaltSize() {
        GeoServerPBEByteEncryptor encryptor = createLegacyEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");
        encryptor.setSaltSizeBytes(16);
        byte[] encrypted = encryptor.encrypt(MESSAGE);
        assertArrayEquals(MESSAGE, encryptor.decrypt(encrypted));
    }

    @Test
    void testInvalidSaltSizeThrowsException() {
        GeoServerPBEByteEncryptor encryptor = new GeoServerPBEByteEncryptor();
        assertThrows(IllegalArgumentException.class, () -> encryptor.setSaltSizeBytes(0));
        assertThrows(IllegalArgumentException.class, () -> encryptor.setSaltSizeBytes(-1));
    }

    @Test
    void testCustomKeyObtentionIterations() {
        GeoServerPBEByteEncryptor encryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);
        encryptor.setKeyObtentionIterations(5000);
        byte[] encrypted = encryptor.encrypt(MESSAGE);
        assertArrayEquals(MESSAGE, encryptor.decrypt(encrypted));
    }

    @Test
    void testInvalidKeyObtentionIterationsThrowsException() {
        GeoServerPBEByteEncryptor encryptor = new GeoServerPBEByteEncryptor();
        assertThrows(IllegalArgumentException.class, () -> encryptor.setKeyObtentionIterations(0));
        assertThrows(IllegalArgumentException.class, () -> encryptor.setKeyObtentionIterations(-1));
    }

    @Test
    void testClearPasswordChangesEncryptionKey() {
        GeoServerPBEByteEncryptor encryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);
        byte[] encrypted = encryptor.encrypt(MESSAGE);
        encryptor.clearPassword();
        assertThrows(Exception.class, () -> encryptor.decrypt(encrypted));
    }

    @Test
    void testEncryptWithoutPasswordThrowsException() {
        GeoServerPBEByteEncryptor encryptor = new GeoServerPBEByteEncryptor();
        encryptor.setAlgorithm("PBEWITHMD5ANDDES");
        assertThrows(IllegalStateException.class, () -> encryptor.encrypt(MESSAGE));
    }

    @Test
    void testEncryptWithoutAlgorithmThrowsException() {
        GeoServerPBEByteEncryptor encryptor = new GeoServerPBEByteEncryptor();
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

    private static GeoServerPBEByteEncryptor createLegacyEncryptor(String algorithm, String providerName) {
        GeoServerPBEByteEncryptor encryptor = new GeoServerPBEByteEncryptor();
        encryptor.setPasswordCharArray(PASSWORD);
        encryptor.setAlgorithm(algorithm);
        if (providerName != null) {
            encryptor.setProviderName(providerName);
        }
        return encryptor;
    }
}
