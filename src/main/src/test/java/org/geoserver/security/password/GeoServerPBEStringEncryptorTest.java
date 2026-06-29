/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class GeoServerPBEStringEncryptorTest {

    private static final char[] PASSWORD = "geoserver".toCharArray();

    @BeforeAll
    static void registerBouncyCastleProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void testStringEncryptDecrypt() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor("PBEWITHMD5ANDDES", null);
        String original = "secret-password-cafe\u0301";
        String encrypted = encryptor.encrypt(original);
        assertNotNull(encrypted);
        assertEquals(original, encryptor.decrypt(encrypted));
    }

    @Test
    void testStringEncryptDecryptWithBC() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");
        String original = "secret-password-cafe\u0301";
        String encrypted = encryptor.encrypt(original);
        assertNotNull(encrypted);
        assertEquals(original, encryptor.decrypt(encrypted));
    }

    @Test
    void testStringEncryptedByJasyptCanBeDecryptedByGeoserver() {
        StandardPBEStringEncryptor jasyptEncryptor =
                createJasyptStringEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");
        GeoServerPBEStringEncryptor legacyEncryptor = createGeoServerEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");

        String encrypted = jasyptEncryptor.encrypt("secret-password-cafe\u0301");

        assertEquals("secret-password-cafe\u0301", legacyEncryptor.decrypt(encrypted));
    }

    @Test
    void testStringEncryptedByGeoserverCanBeDecryptedByJasypt() {
        StandardPBEStringEncryptor jasyptEncryptor =
                createJasyptStringEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");
        GeoServerPBEStringEncryptor legacyEncryptor = createGeoServerEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");

        String encrypted = legacyEncryptor.encrypt("secret-password-cafe\u0301");

        assertEquals("secret-password-cafe\u0301", jasyptEncryptor.decrypt(encrypted));
    }

    @Test
    void testStringEncryptDecryptEmpty() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor("PBEWITHMD5ANDDES", null);
        String encrypted = encryptor.encrypt("");
        assertNotNull(encrypted);
        assertEquals("", encryptor.decrypt(encrypted));
    }

    @Test
    void testStringEncryptNullReturnsNull() {
        GeoServerPBEStringEncryptor encryptor = createGeoServerEncryptor("PBEWITHMD5ANDDES", null);
        assertNull(encryptor.encrypt((String) null));
        assertNull(encryptor.decrypt((String) null));
    }

    private static StandardPBEStringEncryptor createJasyptStringEncryptor(String algorithm, String providerName) {
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
