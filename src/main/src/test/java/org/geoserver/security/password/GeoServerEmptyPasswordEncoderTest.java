package org.geoserver.security.password;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class GeoServerEmptyPasswordEncoderTest {

    private GeoServerEmptyPasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        passwordEncoder = new GeoServerEmptyPasswordEncoder();
        passwordEncoder.setPrefix("empty");
    }

    @Test
    void testEncodePasswordString() {
        String encoded = passwordEncoder.encodePassword("anything", null);
        assertEquals("empty:", encoded);
    }

    @Test
    void testEncodePasswordCharArray() {
        String encoded = passwordEncoder.encodePassword("anything".toCharArray(), null);
        assertEquals("empty:", encoded);
    }

    @Test
    void testEncode() {
        String encoded = passwordEncoder.encode("anything");
        assertEquals("empty:", encoded);
    }

    @Test
    void testEncodeEmptyString() {
        String encoded = passwordEncoder.encode("");
        assertEquals("empty:", encoded);
    }

    @Test
    void testIsPasswordValidAlwaysFalse() {
        String encoded = passwordEncoder.encode("anything");
        assertFalse(passwordEncoder.isPasswordValid(encoded, "anything", null));
        assertFalse(passwordEncoder.isPasswordValid(encoded, "anything".toCharArray(), null));
        assertFalse(passwordEncoder.isPasswordValid(encoded, "", null));
        assertFalse(passwordEncoder.isPasswordValid(encoded, "wrong", null));
    }

    @Test
    void testIsResponsibleForEncoding() {
        assertTrue(passwordEncoder.isResponsibleForEncoding("empty:"));
        assertTrue(passwordEncoder.isResponsibleForEncoding("empty:someencodeddata"));
        assertFalse(passwordEncoder.isResponsibleForEncoding("digest1:hash"));
        assertFalse(passwordEncoder.isResponsibleForEncoding(""));
        assertFalse(passwordEncoder.isResponsibleForEncoding(null));
    }

    @Test
    void testEncodeConsistentWithEncodePassword() {
        String fromEncode = passwordEncoder.encode("test");
        String fromEncodePassword = passwordEncoder.encodePassword("test", null);
        assertEquals(fromEncodePassword, fromEncode);
    }
}
