/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.lang.reflect.InvocationTargetException;
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
        LegacyPBEByteEncryptor legacyEncryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);

        byte[] encrypted = jasyptEncryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, legacyEncryptor.decrypt(encrypted));
    }

    @Test
    void testPbeWithMd5AndDesCanBeDecryptedByJasypt() {
        StandardPBEByteEncryptor jasyptEncryptor = createJasyptEncryptor("PBEWITHMD5ANDDES", null);
        LegacyPBEByteEncryptor legacyEncryptor = createLegacyEncryptor("PBEWITHMD5ANDDES", null);

        byte[] encrypted = legacyEncryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, jasyptEncryptor.decrypt(encrypted));
    }

    @Test
    void testPbeWithSha256And256BitAesCbcBcCanDecryptJasyptEncryptedBytes() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        StandardPBEByteEncryptor jasyptEncryptor =
                createJasyptEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");
        LegacyPBEByteEncryptor legacyEncryptor =
                createLegacyEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");

        byte[] encrypted = jasyptEncryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, legacyEncryptor.decrypt(encrypted));
    }

    @Test
    void testPbeWithSha256And256BitAesCbcBcCanBeDecryptedByJasypt() {
        StandardPBEByteEncryptor jasyptEncryptor =
                createJasyptEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");
        LegacyPBEByteEncryptor legacyEncryptor =
                createLegacyEncryptor("PBEWITHSHA256AND256BITAES-CBC-BC", "BC");

        byte[] encrypted = legacyEncryptor.encrypt(MESSAGE);

        assertArrayEquals(MESSAGE, jasyptEncryptor.decrypt(encrypted));
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

    private static LegacyPBEByteEncryptor createLegacyEncryptor(String algorithm, String providerName) {
        LegacyPBEByteEncryptor encryptor = new LegacyPBEByteEncryptor();
        encryptor.setPasswordCharArray(PASSWORD);
        encryptor.setAlgorithm(algorithm);
        if (providerName != null) {
            encryptor.setProviderName(providerName);
        }
        return encryptor;
    }
}