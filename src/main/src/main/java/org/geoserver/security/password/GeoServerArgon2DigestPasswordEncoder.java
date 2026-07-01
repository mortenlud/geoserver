/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import com.google.common.base.Preconditions;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Password encoder backed by Argon2id.
 */
public class GeoServerArgon2DigestPasswordEncoder extends AbstractGeoserverPasswordEncoder {
    private final Argon2PasswordEncoder digester;

    public GeoServerArgon2DigestPasswordEncoder() {
        this(16, 32, 1, 4096, 3);
    }

    /**
     * @param saltLength length of the random salt in bytes
     * @param hashLength length of the derived hash in bytes
     * @param parallelism degree of parallelism (number of threads)
     * @param memory memory cost in KiB
     * @param iterations time cost (number of iterations)
     */
    public GeoServerArgon2DigestPasswordEncoder(
            int saltLength, int hashLength, int parallelism, int memory, int iterations) {
        Preconditions.checkArgument(saltLength > 0, "saltLength must be positive");
        Preconditions.checkArgument(hashLength > 0, "hashLength must be positive");
        Preconditions.checkArgument(parallelism > 0, "parallelism must be positive");
        Preconditions.checkArgument(memory > 0, "memory must be positive");
        Preconditions.checkArgument(iterations > 0, "iterations must be positive");
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
