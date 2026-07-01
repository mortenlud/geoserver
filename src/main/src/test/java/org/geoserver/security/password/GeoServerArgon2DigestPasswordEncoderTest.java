/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

public class GeoServerArgon2DigestPasswordEncoderTest {

    @Test
    public void testDefaultConstructor() {
        GeoServerArgon2DigestPasswordEncoder passwordEncoder = new GeoServerArgon2DigestPasswordEncoder();
        passwordEncoder.setPrefix("digest2");

        String encoded = passwordEncoder.encodePassword("password", null);
        assertNotEquals("password", encoded);
        assertTrue(encoded.startsWith("digest2:"));

        assertTrue(passwordEncoder.isPasswordValid(encoded, "password", null));
        assertFalse(passwordEncoder.isPasswordValid(encoded, "wrong_password", null));
    }

    @Test
    public void testConstructorRejectsNonPositiveSaltLength() {
        assertThrows(IllegalArgumentException.class, () -> new GeoServerArgon2DigestPasswordEncoder(0, 32, 1, 4096, 3));
    }

    @Test
    public void testConstructorRejectsNonPositiveHashLength() {
        assertThrows(IllegalArgumentException.class, () -> new GeoServerArgon2DigestPasswordEncoder(16, 0, 1, 4096, 3));
    }

    @Test
    public void testConstructorRejectsNonPositiveParallelism() {
        assertThrows(
                IllegalArgumentException.class, () -> new GeoServerArgon2DigestPasswordEncoder(16, 32, 0, 4096, 3));
    }

    @Test
    public void testConstructorRejectsNonPositiveMemory() {
        assertThrows(IllegalArgumentException.class, () -> new GeoServerArgon2DigestPasswordEncoder(16, 32, 1, 0, 3));
    }

    @Test
    public void testConstructorRejectsNonPositiveIterations() {
        assertThrows(
                IllegalArgumentException.class, () -> new GeoServerArgon2DigestPasswordEncoder(16, 32, 1, 4096, 0));
    }

    @Test
    public void testEmptyPassword() {
        GeoServerArgon2DigestPasswordEncoder passwordEncoder =
                new GeoServerArgon2DigestPasswordEncoder(16, 32, 1, 4096, 3);
        passwordEncoder.setPrefix("digest2");

        String encoded = passwordEncoder.encodePassword("", null);
        assertNotEquals("", encoded);
        assertTrue(encoded.startsWith("digest2:"));
    }

    @Test
    public void testStringEncoder() {
        GeoServerArgon2DigestPasswordEncoder passwordEncoder =
                new GeoServerArgon2DigestPasswordEncoder(16, 32, 1, 4096, 3);
        passwordEncoder.setPrefix("digest2");

        String encodedPassword = passwordEncoder.encodePassword("password", null);
        assertNotEquals("password", encodedPassword);
        assertTrue(encodedPassword.startsWith("digest2:"));

        assertTrue(passwordEncoder.isPasswordValid(encodedPassword, "password", null));
        assertFalse(passwordEncoder.isPasswordValid(encodedPassword, "wrong_password", null));
    }

    @Test
    public void testStringEncoderExoticPassword() {
        GeoServerArgon2DigestPasswordEncoder passwordEncoder =
                new GeoServerArgon2DigestPasswordEncoder(16, 32, 1, 4096, 3);
        passwordEncoder.setPrefix("digest2");

        String encodedPassword = passwordEncoder.encodePassword("øæåñüéöàçдя", null);
        assertNotEquals("øæåñüéöàçдя", encodedPassword);
        assertTrue(encodedPassword.startsWith("digest2:"));

        assertTrue(passwordEncoder.isPasswordValid(encodedPassword, "øæåñüéöàçдя", null));
        assertFalse(passwordEncoder.isPasswordValid(encodedPassword, "wrong_password", null));
    }

    @Test
    public void testByteArrayEncoder() {
        GeoServerArgon2DigestPasswordEncoder passwordEncoder =
                new GeoServerArgon2DigestPasswordEncoder(16, 32, 1, 4096, 3);
        passwordEncoder.setPrefix("digest2");

        String encoded = passwordEncoder.encodePassword("geoserver".toCharArray(), null);
        assertNotEquals("geoserver", encoded);
        assertTrue(encoded.startsWith("digest2:"));

        assertTrue(passwordEncoder.isPasswordValid(encoded, "geoserver".toCharArray(), null));
        assertFalse(passwordEncoder.isPasswordValid(encoded, "wrong_password".toCharArray(), null));
    }

    @Test
    public void testByteArrayEncoderExoticPassword() {
        GeoServerArgon2DigestPasswordEncoder passwordEncoder =
                new GeoServerArgon2DigestPasswordEncoder(16, 32, 1, 4096, 3);
        passwordEncoder.setPrefix("digest2");

        String encoded = passwordEncoder.encodePassword("øæåñüéöàçдя".toCharArray(), null);
        assertNotEquals("øæåñüéöàçдя", encoded);
        assertTrue(encoded.startsWith("digest2:"));

        assertTrue(passwordEncoder.isPasswordValid(encoded, "øæåñüéöàçдя".toCharArray(), null));
        assertFalse(passwordEncoder.isPasswordValid(encoded, "wrong_password".toCharArray(), null));
    }

    @Test
    public void testEncode() {
        GeoServerArgon2DigestPasswordEncoder passwordEncoder =
                new GeoServerArgon2DigestPasswordEncoder(16, 32, 1, 4096, 3);
        passwordEncoder.setPrefix("digest2");

        String encoded = passwordEncoder.encode("geoserver");
        assertNotEquals("geoserver", encoded);
        assertNotNull(encoded);
        assertFalse(encoded.contains("digest2"));

        assertTrue(passwordEncoder.isPasswordValid(encoded, "geoserver".toCharArray(), null));
        assertFalse(passwordEncoder.isPasswordValid(encoded, "wrong_password".toCharArray(), null));
    }

    @Test
    public void testSpringArgon2Compatibility() {
        // Verify BC-based encoder can validate hashes produced by Spring Security's Argon2PasswordEncoder
        Argon2PasswordEncoder springEncoder = new Argon2PasswordEncoder(16, 32, 1, 4096, 3);
        String springEncoded = springEncoder.encode("password");

        GeoServerArgon2DigestPasswordEncoder ourEncoder = new GeoServerArgon2DigestPasswordEncoder(16, 32, 1, 4096, 3);
        ourEncoder.setPrefix("digest2");

        // Our encoder should validate a password against a Spring-encoded hash
        assertTrue(ourEncoder.isPasswordValid(springEncoded, "password", null));
        assertFalse(ourEncoder.isPasswordValid(springEncoded, "wrong_password", null));
        assertTrue(ourEncoder.isPasswordValid(springEncoded, "password".toCharArray(), null));
        assertFalse(ourEncoder.isPasswordValid(springEncoded, "wrong_password".toCharArray(), null));

        // Spring encoder should validate a password against our encoded hash
        String ourEncoded = ourEncoder.encode("password");
        assertTrue(springEncoder.matches("password", ourEncoded));
        assertFalse(springEncoder.matches("wrong_password", ourEncoded));
    }

    @Test
    public void testSpringArgon2CompatibilityExoticPassword() {
        Argon2PasswordEncoder springEncoder = new Argon2PasswordEncoder(16, 32, 1, 4096, 3);
        String springEncoded = springEncoder.encode("øæåñüéöàçдя");

        GeoServerArgon2DigestPasswordEncoder ourEncoder = new GeoServerArgon2DigestPasswordEncoder(16, 32, 1, 4096, 3);
        ourEncoder.setPrefix("digest2");

        assertTrue(ourEncoder.isPasswordValid(springEncoded, "øæåñüéöàçдя", null));
        assertFalse(ourEncoder.isPasswordValid(springEncoded, "wrong_password", null));
        assertTrue(ourEncoder.isPasswordValid(springEncoded, "øæåñüéöàçдя".toCharArray(), null));
        assertFalse(ourEncoder.isPasswordValid(springEncoded, "wrong_password".toCharArray(), null));

        String ourEncoded = ourEncoder.encode("øæåñüéöàçдя");
        assertTrue(springEncoder.matches("øæåñüéöàçдя", ourEncoded));
        assertFalse(springEncoder.matches("wrong_password", ourEncoded));
    }

    @Test
    public void testEncodeExoticPassword() {
        GeoServerArgon2DigestPasswordEncoder passwordEncoder =
                new GeoServerArgon2DigestPasswordEncoder(16, 32, 1, 4096, 3);
        passwordEncoder.setPrefix("digest2");

        String encoded = passwordEncoder.encode("øæåñüéöàçдя");
        assertNotEquals("øæåñüéöàçдя", encoded);
        assertNotNull(encoded);
        assertFalse(encoded.contains("digest2"));

        assertTrue(passwordEncoder.isPasswordValid(encoded, "øæåñüéöàçдя".toCharArray(), null));
        assertFalse(passwordEncoder.isPasswordValid(encoded, "wrong_password".toCharArray(), null));
    }
}
