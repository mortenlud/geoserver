/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Password encoder which uses digest encoding This encoder cannot be used for authentication mechanisms needing the
 * plain text password. (Http digest authentication as an example)
 *
 * <p>The salt parameter is not used, this implementation computes a random salt as default.
 *
 * <p>{@link #isPasswordValid(String, String, Object)} {@link #encodePassword(String, Object)}
 *
 * @author christian
 */
public class GeoServerArgon2DigestPasswordEncoder extends AbstractGeoserverPasswordEncoder {
    private final Argon2PasswordEncoder digester;

    public GeoServerArgon2DigestPasswordEncoder(
            int saltLength, int hashLength, int parallelism, int memory, int iterations) {
        digester = new Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations);
        setReversible(false);
    }

    @Override
    protected PasswordEncoder createStringEncoder() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                return digester.encode(rawPassword);
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return digester.matches(rawPassword, encodedPassword);
            }
        };
    }

    @Override
    protected CharArrayPasswordEncoder createCharEncoder() {
        return new CharArrayPasswordEncoder() {
            @Override
            public String encodePassword(char[] rawPassword, Object salt) {
                return digester.encode(java.nio.CharBuffer.wrap(rawPassword));
            }

            @Override
            public boolean isPasswordValid(String encPassword, char[] rawPassword, Object salt) {
                return digester.matches(java.nio.CharBuffer.wrap(rawPassword), encPassword);
            }
        };
    }

    @Override
    public PasswordEncodingType getEncodingType() {
        return PasswordEncodingType.DIGEST;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return digester.encode(rawPassword);
    }
}
