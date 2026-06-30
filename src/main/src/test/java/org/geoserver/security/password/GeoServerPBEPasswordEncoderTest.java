/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Base64;
import org.geoserver.platform.resource.Resource;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.KeyStoreProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class GeoServerPBEPasswordEncoderTest {

    @Mock
    private GeoServerSecurityManager securityManager;

    @Mock
    private KeyStoreProvider keyStoreProvider;

    @Mock
    private GeoServerUserGroupService userGroupService;

    @Mock
    private Resource resource;

    private AutoCloseable mockCloser;

    @BeforeEach
    public void setUp() throws IOException {
        mockCloser = MockitoAnnotations.openMocks(this);

        when(securityManager.getKeyStoreProvider()).thenReturn(keyStoreProvider);
        when(userGroupService.getName()).thenReturn("testService");
        when(keyStoreProvider.getResource()).thenReturn(resource);
        when(resource.path()).thenReturn("/tmp/test.keystore");
        when(keyStoreProvider.hasUserGroupKey(anyString())).thenReturn(true);
        when(keyStoreProvider.aliasForGroupService(anyString())).thenReturn("testAlias");
        when(keyStoreProvider.containsAlias(anyString())).thenReturn(true);
        when(keyStoreProvider.getSecretKey(anyString()))
                .thenReturn(new javax.crypto.spec.SecretKeySpec("testKey123".getBytes(), "DES"));
    }

    @AfterEach
    public void tearDown() throws Exception {
        mockCloser.close();
    }

    private GeoServerPBEPasswordEncoder createEncoder() throws IOException {
        GeoServerPBEPasswordEncoder encoder = new GeoServerPBEPasswordEncoder();
        encoder.initialize(securityManager);
        encoder.initializeFor(userGroupService);
        return encoder;
    }

    @Test
    public void testEncryptDecryptStringPBEWITHMD5ANDDES() throws IOException {
        GeoServerPBEPasswordEncoder encoder = createEncoder();
        encoder.setAlgorithm("PBEWITHMD5ANDDES");
        encoder.setPrefix("crypto1");

        String original = "testPasswordCafe\u0301";
        String encoded = encoder.encodePassword(original, null);
        assertNotNull(encoded);
        assertNotEquals(original, encoded);
        assertTrue(encoded.startsWith("crypto1"), "Encoded string should start with the specified prefix");

        String decoded = encoder.decode(encoded);
        assertNotNull(decoded);
        assertArrayEquals(original.toCharArray(), decoded.toCharArray());
    }

    @Test
    public void testEncryptDecryptByteArrayPBEWITHMD5ANDDES() throws IOException {
        GeoServerPBEPasswordEncoder encoder = createEncoder();
        encoder.setAlgorithm("PBEWITHMD5ANDDES");
        encoder.setPrefix("crypto1");

        char[] original = "testPasswordCafe\u0301".toCharArray();
        String encoded = encoder.encodePassword(original, null);
        assertNotNull(encoded);
        assertTrue(encoded.startsWith("crypto1"), "Encoded string should start with the specified prefix");

        char[] decoded = encoder.decodeToCharArray(encoded);
        assertNotNull(decoded);
        assertArrayEquals(original, decoded);
    }

    @Test
    public void testEncryptDecryptStringPBEWITHSHA256AND256BITAESCBCBC() throws IOException {
        GeoServerPBEPasswordEncoder encoder = createEncoder();
        encoder.setAlgorithm("PBEWITHSHA256AND256BITAES-CBC-BC");
        encoder.setPrefix("crypto2");
        encoder.setProviderName("BC");

        String original = "testPasswordCafe\u0301";
        String encoded = encoder.encodePassword(original, null);
        assertNotNull(encoded);
        assertNotEquals(original, encoded);
        assertTrue(encoded.startsWith("crypto2"), "Encoded string should start with the specified prefix");

        String decoded = encoder.decode(encoded);
        assertNotNull(decoded);
        assertArrayEquals(original.toCharArray(), decoded.toCharArray());
    }

    @Test
    public void testEncryptDecryptByteArrayPBEWITHSHA256AND256BITAESCBCBC() throws IOException {
        GeoServerPBEPasswordEncoder encoder = createEncoder();
        encoder.setAlgorithm("PBEWITHSHA256AND256BITAES-CBC-BC");
        encoder.setPrefix("crypto2");
        encoder.setProviderName("BC");

        char[] original = "testPasswordCafe\u0301".toCharArray();
        String encoded = encoder.encodePassword(original, null);
        assertNotNull(encoded);
        assertTrue(encoded.startsWith("crypto2"), "Encoded string should start with the specified prefix");

        char[] decoded = encoder.decodeToCharArray(encoded);
        assertNotNull(decoded);
        assertArrayEquals(original, decoded);
    }

    @Test
    public void testEncryptDecryptEmptyPassword() throws IOException {
        GeoServerPBEPasswordEncoder encoder = createEncoder();
        encoder.setAlgorithm("PBEWITHMD5ANDDES");
        encoder.setPrefix("crypto1");

        String encoded = encoder.encodePassword("", null);
        assertNotNull(encoded);
        assertTrue(encoded.startsWith("crypto1"));

        String decoded = encoder.decode(encoded);
        assertEquals("", decoded);
    }

    @Test
    public void testEncryptDecryptSpecialCharacters() throws IOException {
        GeoServerPBEPasswordEncoder encoder = createEncoder();
        encoder.setAlgorithm("PBEWITHMD5ANDDES");
        encoder.setPrefix("crypto1");

        String original = "æøå!@#$%^&*()_+-=[]{}|;':\",./<>?~";
        String encoded = encoder.encodePassword(original, null);
        assertNotNull(encoded);
        assertEquals(original, encoder.decode(encoded));
    }

    @Test
    public void testDecryptWithWrongPrefix() throws IOException {
        GeoServerPBEPasswordEncoder encoder = createEncoder();
        encoder.setAlgorithm("PBEWITHMD5ANDDES");
        encoder.setPrefix("crypto1");

        String encoded = encoder.encodePassword("testPasswordCafe\u0301", null);

        // changing the prefix causes prefix-stripping to leave the "crypto1:" trailer intact,
        // which is not valid Base64 → decode throws
        encoder.setPrefix("wrongPrefix");
        assertThrows(Exception.class, () -> encoder.decode(encoded));
    }

    @Test
    public void testDecryptCorruptedData() throws IOException {
        GeoServerPBEPasswordEncoder encoder = createEncoder();
        encoder.setAlgorithm("PBEWITHMD5ANDDES");
        encoder.setPrefix("crypto1");

        assertThrows(Exception.class, () -> encoder.decode("crypto1:!!!invalid-base64!!!"));
    }

    @Test
    public void testDecryptTruncatedData() throws IOException {
        GeoServerPBEPasswordEncoder encoder = createEncoder();
        encoder.setAlgorithm("PBEWITHMD5ANDDES");
        encoder.setPrefix("crypto1");

        // valid Base64 but decodes to fewer than the 8-byte salt → should fail
        String truncated = "crypto1:" + Base64.getEncoder().encodeToString(new byte[3]);
        assertThrows(IllegalArgumentException.class, () -> encoder.decode(truncated));
    }

    @Test
    public void testMultipleEncryptDecryptCycles() throws IOException {
        GeoServerPBEPasswordEncoder encoder = createEncoder();
        encoder.setAlgorithm("PBEWITHMD5ANDDES");
        encoder.setPrefix("crypto1");

        String original = "testPasswordCafe\u0301";
        for (int i = 0; i < 5; i++) {
            String encoded = encoder.encodePassword(original, null);
            assertEquals(original, encoder.decode(encoded));
        }
    }

    @Test
    public void testIsPasswordValidString() throws IOException {
        GeoServerPBEPasswordEncoder encoder = createEncoder();
        encoder.setAlgorithm("PBEWITHMD5ANDDES");
        encoder.setPrefix("crypto1");

        String password = "mySecretPassword";
        String encoded = encoder.encodePassword(password, null);

        assertTrue(encoder.isPasswordValid(encoded, password, null));
        assertFalse(encoder.isPasswordValid(encoded, "wrongPassword", null));
        assertFalse(encoder.isPasswordValid(null, password, null));
    }

    @Test
    public void testIsPasswordValidCharArray() throws IOException {
        GeoServerPBEPasswordEncoder encoder = createEncoder();
        encoder.setAlgorithm("PBEWITHMD5ANDDES");
        encoder.setPrefix("crypto1");

        String password = "mySecretPassword";
        String encoded = encoder.encodePassword(password, null);

        assertTrue(encoder.isPasswordValid(encoded, password.toCharArray(), null));
        assertFalse(encoder.isPasswordValid(encoded, "wrongPassword".toCharArray(), null));
        assertFalse(encoder.isPasswordValid(null, password.toCharArray(), null));
    }

    @Test
    public void testIsResponsibleForEncoding() throws IOException {
        GeoServerPBEPasswordEncoder encoder = createEncoder();
        encoder.setAlgorithm("PBEWITHMD5ANDDES");
        encoder.setPrefix("crypto1");

        assertTrue(encoder.isResponsibleForEncoding("crypto1:abcdef"));
        assertFalse(encoder.isResponsibleForEncoding("other:abcdef"));
        assertFalse(encoder.isResponsibleForEncoding(null));
        assertFalse(encoder.isResponsibleForEncoding(""));
    }

    @Test
    public void testCrossPathCompatibility() throws IOException {
        GeoServerPBEPasswordEncoder encoder = createEncoder();
        encoder.setAlgorithm("PBEWITHMD5ANDDES");
        encoder.setPrefix("crypto1");

        String password = "crossPathTest";
        String encoded = encoder.encodePassword(password, null);

        char[] decodedChars = encoder.decodeToCharArray(encoded);
        assertArrayEquals(password.toCharArray(), decodedChars);

        String encodedFromChars = encoder.encodePassword(password.toCharArray(), null);
        assertEquals(password, encoder.decode(encodedFromChars));

        assertTrue(encoder.isPasswordValid(encoded, password, null));
        assertTrue(encoder.isPasswordValid(encoded, password.toCharArray(), null));
    }
}
