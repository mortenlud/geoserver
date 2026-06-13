package org.geoserver.security.password;

import org.geoserver.platform.resource.Resource;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.KeyStoreProvider;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;

import static org.junit.Assert.*;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.when;

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

    @Before
    public void setUp() throws IOException {
        MockitoAnnotations.initMocks(this);
        passwordEncoder = new GeoServerPBEPasswordEncoder();

        when(securityManager.getKeyStoreProvider()).thenReturn(keyStoreProvider);
        when(userGroupService.getName()).thenReturn("testService");
        when(keyStoreProvider.getResource()).thenReturn(resource);
        when(resource.path()).thenReturn("/tmp/test.keystore");
        when(keyStoreProvider.hasUserGroupKey(anyString())).thenReturn(true);
        when(keyStoreProvider.aliasForGroupService(anyString())).thenReturn("testAlias");
        when(keyStoreProvider.containsAlias(anyString())).thenReturn(true);
        when(keyStoreProvider.getSecretKey(anyString())).thenReturn(
                new javax.crypto.spec.SecretKeySpec("testKey123".getBytes(), "DES"));

        passwordEncoder.initialize(securityManager);
        passwordEncoder.initializeFor(userGroupService);
    }

    @Test
    public void testEncryptDecryptStringPBEWITHMD5ANDDES() throws IOException {
        passwordEncoder.setAlgorithm("PBEWITHMD5ANDDES");
        passwordEncoder.setPrefix("crypto1");

        String original = "testPassword123";
        String encoded = passwordEncoder.encodePassword(original, null);
        assertNotNull(encoded);
        assertNotEquals(original, encoded);
        assertTrue("Encoded string should start with the specified prefix",
                encoded.startsWith("crypto1"));

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
        assertTrue("Encoded string should start with the specified prefix",
                encoded.startsWith("crypto1"));

        char[] decoded = passwordEncoder.decodeToCharArray(encoded);
        assertNotNull(decoded);
        assertArrayEquals(original, decoded);
    }

    @Test
    public void testEncryptDecryptStringPBEWITHSHA256AND256BITAESCBCBC() throws IOException {
        passwordEncoder.setAlgorithm("PBEWITHSHA256AND256BITAES-CBC-BC");
        passwordEncoder.setPrefix("crypto2");
        passwordEncoder.setProviderName("BC");

        String original = "testPassword123";
        String encoded = passwordEncoder.encodePassword(original, null);
        assertNotNull(encoded);
        assertNotEquals(original, encoded);
        assertTrue("Encoded string should start with the specified prefix",
                encoded.startsWith("crypto2"));

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
        assertTrue("Encoded string should start with the specified prefix",
                encoded.startsWith("crypto2"));

        char[] decoded = passwordEncoder.decodeToCharArray(encoded);
        assertNotNull(decoded);
        assertArrayEquals(original, decoded);
    }
}