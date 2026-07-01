/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import java.nio.CharBuffer;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Password encoder backed by Argon2id. Uses Spring Security's {@link Argon2PasswordEncoder} and produces a DIGEST-type
 * encoding. This encoder is not reversible.
 */
public class GeoServerArgon2DigestPasswordEncoder extends AbstractGeoserverPasswordEncoder {

    private final Argon2PasswordEncoder argon2PasswordEncoder;

    /** Default constructor using Argon2id standard parameters (16/32/1/4096/3). */
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
        if (saltLength <= 0) throw new IllegalArgumentException("saltLength must be positive");
        if (hashLength <= 0) throw new IllegalArgumentException("hashLength must be positive");
        if (parallelism <= 0) throw new IllegalArgumentException("parallelism must be positive");
        if (memory <= 0) throw new IllegalArgumentException("memory must be positive");
        if (iterations <= 0) throw new IllegalArgumentException("iterations must be positive");
        argon2PasswordEncoder = new Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations);
        setReversible(false);
    }

    @Override
    protected PasswordEncoder createStringEncoder() {
        return argon2PasswordEncoder;
    }

    @Override
    protected CharArrayPasswordEncoder createCharEncoder() {
        return new CharArrayPasswordEncoder() {
            @Override
            public String encodePassword(char[] rawPassword, Object salt) {
                return argon2PasswordEncoder.encode(CharBuffer.wrap(rawPassword));
            }

            @Override
            public boolean isPasswordValid(String encPassword, char[] rawPassword, Object salt) {
                return argon2PasswordEncoder.matches(CharBuffer.wrap(rawPassword), encPassword);
            }
        };
    }

    @Override
    public PasswordEncodingType getEncodingType() {
        return PasswordEncodingType.DIGEST;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return argon2PasswordEncoder.encode(rawPassword);
    }
}
