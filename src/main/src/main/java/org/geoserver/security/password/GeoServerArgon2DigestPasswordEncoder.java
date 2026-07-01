/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.geoserver.security.SecurityUtils.scramble;
import static org.geoserver.security.SecurityUtils.toBytes;

import com.google.common.base.Preconditions;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.Arrays;
import org.springframework.security.crypto.password.PasswordEncoder;

/** Password encoder backed by Argon2id. */
public class GeoServerArgon2DigestPasswordEncoder extends AbstractGeoserverPasswordEncoder {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final int saltLength;
    private final int hashLength;
    private final int parallelism;
    private final int memory;
    private final int iterations;

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
        this.saltLength = saltLength;
        this.hashLength = hashLength;
        this.parallelism = parallelism;
        this.memory = memory;
        this.iterations = iterations;
        setReversible(false);
    }

    @Override
    protected PasswordEncoder createStringEncoder() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                if (rawPassword == null) {
                    return null;
                }
                return doEncode(rawPassword);
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                if (rawPassword == null || encodedPassword == null) {
                    return false;
                }
                return doMatches(rawPassword, encodedPassword);
            }
        };
    }

    @Override
    protected CharArrayPasswordEncoder createCharEncoder() {
        return new CharArrayPasswordEncoder() {
            @Override
            public String encodePassword(char[] rawPassword, Object salt) {
                if (rawPassword == null) {
                    throw new IllegalArgumentException("rawPassword cannot be null");
                }
                return doEncode(rawPassword);
            }

            @Override
            public boolean isPasswordValid(String encPassword, char[] rawPassword, Object salt) {
                if (encPassword == null || encPassword.isEmpty() || rawPassword == null) {
                    return false;
                }
                return doMatches(rawPassword, encPassword);
            }
        };
    }

    @Override
    public PasswordEncodingType getEncodingType() {
        return PasswordEncodingType.DIGEST;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            return null;
        }
        return doEncode(rawPassword);
    }

    private String doEncode(char[] password) {
        byte[] passwordBytes = toBytes(password, StandardCharsets.UTF_8);
        try {
            return hash(passwordBytes);
        } finally {
            scramble(passwordBytes);
        }
    }

    private String doEncode(CharSequence password) {
        char[] chars = toCharArray(password);
        try {
            byte[] passwordBytes = toBytes(chars, StandardCharsets.UTF_8);
            try {
                return hash(passwordBytes);
            } finally {
                scramble(passwordBytes);
            }
        } finally {
            scramble(chars);
        }
    }

    private boolean doMatches(char[] password, String encoded) {
        byte[] passwordBytes = toBytes(password, StandardCharsets.UTF_8);
        try {
            return verify(passwordBytes, encoded);
        } finally {
            scramble(passwordBytes);
        }
    }

    private boolean doMatches(CharSequence password, String encoded) {
        char[] chars = toCharArray(password);
        try {
            byte[] passwordBytes = toBytes(chars, StandardCharsets.UTF_8);
            try {
                return verify(passwordBytes, encoded);
            } finally {
                scramble(passwordBytes);
            }
        } finally {
            scramble(chars);
        }
    }

    private static char[] toCharArray(CharSequence seq) {
        char[] chars = new char[seq.length()];
        for (int i = 0; i < seq.length(); i++) {
            chars[i] = seq.charAt(i);
        }
        return chars;
    }

    private static byte[] generateSalt(int length) {
        byte[] salt = new byte[length];
        RANDOM.nextBytes(salt);
        return salt;
    }

    private String hash(byte[] passwordBytes) {
        byte[] salt = generateSalt(saltLength);
        byte[] hash = new byte[hashLength];
        Argon2Parameters params = buildParams(salt);
        try {
            Argon2BytesGenerator gen = new Argon2BytesGenerator();
            gen.init(params);
            gen.generateBytes(passwordBytes, hash);
            return formatEncoded(salt, hash, memory, iterations, parallelism);
        } finally {
            params.clear();
            scramble(salt);
            scramble(hash);
        }
    }

    private boolean verify(byte[] passwordBytes, String encoded) {
        String[] parts = encoded.split("\\$");
        if (parts.length != 6) {
            return false;
        }
        if (!"argon2id".equals(parts[1])) {
            return false;
        }
        if (!"v=19".equals(parts[2])) {
            return false;
        }

        int m;
        int t;
        int p;
        try {
            String[] perf = parts[3].split(",");
            if (perf.length != 3) {
                return false;
            }
            m = Integer.parseInt(perf[0].substring(2));
            t = Integer.parseInt(perf[1].substring(2));
            p = Integer.parseInt(perf[2].substring(2));
        } catch (Exception e) {
            return false;
        }

        byte[] salt;
        byte[] expectedHash;
        try {
            salt = Base64.getDecoder().decode(parts[4]);
            expectedHash = Base64.getDecoder().decode(parts[5]);
        } catch (Exception e) {
            return false;
        }

        byte[] actualHash = new byte[expectedHash.length];
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withParallelism(p)
                .withMemoryAsKB(m)
                .withIterations(t)
                .build();
        try {
            Argon2BytesGenerator gen = new Argon2BytesGenerator();
            gen.init(params);
            gen.generateBytes(passwordBytes, actualHash);
            return Arrays.constantTimeAreEqual(expectedHash, actualHash);
        } finally {
            params.clear();
            scramble(actualHash);
        }
    }

    private Argon2Parameters buildParams(byte[] salt) {
        return new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withParallelism(parallelism)
                .withMemoryAsKB(memory)
                .withIterations(iterations)
                .build();
    }

    private static String formatEncoded(byte[] salt, byte[] hash, int memory, int iterations, int parallelism) {
        return "$argon2id$v=" + Argon2Parameters.ARGON2_VERSION_13 + "$m=" + memory + ",t=" + iterations + ",p="
                + parallelism + "$" + Base64.getEncoder().withoutPadding().encodeToString(salt) + "$"
                + Base64.getEncoder().withoutPadding().encodeToString(hash);
    }
}
