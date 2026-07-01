/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class GeoServerArgon2DigestPasswordEncoderTest {

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
