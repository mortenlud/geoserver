package org.geoserver.security.password;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.when;

import java.io.IOException;
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

    private GeoServerPBEPasswordEncoder passwordEncoder;
    private AutoCloseable mockCloser;

    @BeforeEach
    public void setUp() throws IOException {
        mockCloser = MockitoAnnotations.openMocks(this);
        passwordEncoder = new GeoServerPBEPasswordEncoder();

        when(securityManager.getKeyStoreProvider()).thenReturn(keyStoreProvider);
        when(userGroupService.getName()).thenReturn("testService");
        when(keyStoreProvider.getResource()).thenReturn(resource);
        when(resource.path()).thenReturn("/tmp/test.keystore");
        when(keyStoreProvider.hasUserGroupKey(anyString())).thenReturn(true);
        when(keyStoreProvider.aliasForGroupService(anyString())).thenReturn("testAlias");
        when(keyStoreProvider.containsAlias(anyString())).thenReturn(true);
        when(keyStoreProvider.getSecretKey(anyString()))
                .thenReturn(new javax.crypto.spec.SecretKeySpec("testKey123".getBytes(), "DES"));

        passwordEncoder.initialize(securityManager);
        passwordEncoder.initializeFor(userGroupService);
    }

    @AfterEach
    public void tearDown() throws Exception {
        mockCloser.close();
    }

    @Test
    public void testEncryptDecryptStringPBEWITHMD5ANDDES() {
        passwordEncoder.setAlgorithm("PBEWITHMD5ANDDES");
        passwordEncoder.setPrefix("crypto1");

        String original = "testPassword123";
        String encoded = passwordEncoder.encodePassword(original, null);
        assertNotNull(encoded);
        assertNotEquals(original, encoded);
        assertTrue(encoded.startsWith("crypto1"), "Encoded string should start with the specified prefix");

        String decoded = passwordEncoder.decode(encoded);
        assertNotNull(decoded);
        assertArrayEquals(original.toCharArray(), decoded.toCharArray());
    }

    @Test
    public void testEncryptDecryptByteArrayPBEWITHMD5ANDDES() {
        passwordEncoder.setAlgorithm("PBEWITHMD5ANDDES");
        passwordEncoder.setPrefix("crypto1");

        char[] original = "testPassword123".toCharArray();
        String encoded = passwordEncoder.encodePassword(original, null);
        assertNotNull(encoded);
        assertTrue(encoded.startsWith("crypto1"), "Encoded string should start with the specified prefix");

        char[] decoded = passwordEncoder.decodeToCharArray(encoded);
        assertNotNull(decoded);
        assertArrayEquals(original, decoded);
    }

    @Test
    public void testEncryptDecryptStringPBEWITHSHA256AND256BITAESCBCBC() {
        passwordEncoder.setAlgorithm("PBEWITHSHA256AND256BITAES-CBC-BC");
        passwordEncoder.setPrefix("crypto2");
        passwordEncoder.setProviderName("BC");

        String original = "testPassword123";
        String encoded = passwordEncoder.encodePassword(original, null);
        assertNotNull(encoded);
        assertNotEquals(original, encoded);
        assertTrue(encoded.startsWith("crypto2"), "Encoded string should start with the specified prefix");

        String decoded = passwordEncoder.decode(encoded);
        assertNotNull(decoded);
        assertArrayEquals(original.toCharArray(), decoded.toCharArray());
    }

    @Test
    public void testEncryptDecryptByteArrayPBEWITHSHA256AND256BITAESCBCBC() {
        passwordEncoder.setAlgorithm("PBEWITHSHA256AND256BITAES-CBC-BC");
        passwordEncoder.setPrefix("crypto2");
        passwordEncoder.setProviderName("BC");

        char[] original = "testPassword123".toCharArray();
        String encoded = passwordEncoder.encodePassword(original, null);
        assertNotNull(encoded);
        assertTrue(encoded.startsWith("crypto2"), "Encoded string should start with the specified prefix");

        char[] decoded = passwordEncoder.decodeToCharArray(encoded);
        assertNotNull(decoded);
        assertArrayEquals(original, decoded);
    }

    @Test
    public void testEncryptDecryptEmptyPassword() {
        passwordEncoder.setAlgorithm("PBEWITHMD5ANDDES");
        passwordEncoder.setPrefix("crypto1");

        String encoded = passwordEncoder.encodePassword("", null);
        assertNotNull(encoded);
        assertTrue(encoded.startsWith("crypto1"));

        String decoded = passwordEncoder.decode(encoded);
        assertEquals("", decoded);
    }

    @Test
    public void testEncryptDecryptSpecialCharacters() {
        passwordEncoder.setAlgorithm("PBEWITHMD5ANDDES");
        passwordEncoder.setPrefix("crypto1");

        String original = "æøå!@#$%^&*()_+-=[]{}|;':\",./<>?~";
        String encoded = passwordEncoder.encodePassword(original, null);
        assertNotNull(encoded);
        assertEquals(original, passwordEncoder.decode(encoded));
    }

    @Test
    public void testDecryptWithWrongPrefix() {
        passwordEncoder.setAlgorithm("PBEWITHMD5ANDDES");
        passwordEncoder.setPrefix("crypto1");

        String encoded = passwordEncoder.encodePassword("testPassword123", null);

        passwordEncoder.setPrefix("wrongPrefix");
        assertThrows(Exception.class, () -> passwordEncoder.decode(encoded));
    }

    @Test
    public void testDecryptCorruptedData() {
        passwordEncoder.setAlgorithm("PBEWITHMD5ANDDES");
        passwordEncoder.setPrefix("crypto1");

        assertThrows(Exception.class, () -> passwordEncoder.decode("crypto1:!!!invalid-base64!!!"));
    }

    @Test
    public void testMultipleEncryptDecryptCycles() {
        passwordEncoder.setAlgorithm("PBEWITHMD5ANDDES");
        passwordEncoder.setPrefix("crypto1");

        String original = "testPassword123";
        for (int i = 0; i < 5; i++) {
            String encoded = passwordEncoder.encodePassword(original, null);
            assertEquals(original, passwordEncoder.decode(encoded));
        }
    }

    @Test
    public void testEncodeCharSequence() {
        passwordEncoder.setAlgorithm("PBEWITHMD5ANDDES");
        passwordEncoder.setPrefix("crypto1");

        String original = "testPassword123";
        String encoded = passwordEncoder.encode(original);
        assertNotNull(encoded);
        assertTrue(encoded.startsWith("crypto1"));
        assertEquals(original, passwordEncoder.decode(encoded));
    }
}
