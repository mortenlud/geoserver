/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.geoserver.security.SecurityUtils.scramble;
import static org.geoserver.security.SecurityUtils.toBytes;
import static org.geoserver.security.SecurityUtils.toChars;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.KeyStoreProvider;
import org.geoserver.security.KeyStoreProviderImpl;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Password Encoder using symmetric encryption
 *
 * <p>The salt parameter is not used, this implementation computes a random salt as default.
 *
 * <p>{@link #isPasswordValid(String, String, Object)} {@link #encodePassword(String, Object)}
 *
 * @author christian
 */
public class GeoServerPBEPasswordEncoder extends AbstractGeoserverPasswordEncoder {

    GeoServerPBEByteEncryptor pbeByteEncryptor;
    GeoServerPBEStringEncryptor pbeStringEncryptor;

    private String providerName, algorithm;
    private String keyAliasInKeyStore = KeyStoreProviderImpl.CONFIGPASSWORDKEY;

    private KeyStoreProvider keystoreProvider;

    @Override
    public void initialize(GeoServerSecurityManager securityManager) throws IOException {
        this.keystoreProvider = securityManager.getKeyStoreProvider();
    }

    @Override
    public void initializeFor(GeoServerUserGroupService service) throws IOException {
        if (!keystoreProvider.hasUserGroupKey(service.getName())) {
            throw new IOException("No key alias: "
                    + keystoreProvider.aliasForGroupService(service.getName())
                    + " in key store: "
                    + keystoreProvider.getResource().path());
        }

        keyAliasInKeyStore = keystoreProvider.aliasForGroupService(service.getName());
    }

    public String getProviderName() {
        return providerName;
    }

    public void setProviderName(String providerName) {
        this.providerName = providerName;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getKeyAliasInKeyStore() {
        return keyAliasInKeyStore;
    }

    @Override
    protected PasswordEncoder createStringEncoder() {
        byte[] password = lookupPasswordFromKeyStore();

        char[] chars = toChars(password);
        try {
            pbeStringEncryptor = new GeoServerPBEStringEncryptor();
            pbeStringEncryptor.setPasswordCharArray(chars);

            if (getProviderName() != null && !getProviderName().isEmpty()) {
                pbeStringEncryptor.setProviderName(getProviderName());
            }
            pbeStringEncryptor.setAlgorithm(getAlgorithm());

            PBEPasswordEncoderWrapper encoder = new PBEPasswordEncoderWrapper();
            encoder.setPbeStringEncryptor(pbeStringEncryptor);

            return encoder;
        } finally {
            scramble(password);
            scramble(chars);
        }
    }

    @Override
    protected CharArrayPasswordEncoder createCharEncoder() {
        byte[] password = lookupPasswordFromKeyStore();
        char[] chars = toChars(password);

        pbeByteEncryptor = new GeoServerPBEByteEncryptor();
        pbeByteEncryptor.setPasswordCharArray(chars);

        if (getProviderName() != null && !getProviderName().isEmpty()) {
            pbeByteEncryptor.setProviderName(getProviderName());
        }
        pbeByteEncryptor.setAlgorithm(getAlgorithm());

        return new CharArrayPasswordEncoder() {
            @Override
            public boolean isPasswordValid(String encPass, char[] rawPass, Object salt) {
                byte[] decoded = Base64.getDecoder().decode(encPass.getBytes());
                byte[] decrypted = pbeByteEncryptor.decrypt(decoded);

                char[] chars = toChars(decrypted);
                try {
                    return Arrays.equals(chars, rawPass);
                } finally {
                    scramble(decrypted);
                    scramble(chars);
                }
            }

            @Override
            public String encodePassword(char[] rawPass, Object salt) {
                byte[] bytes = toBytes(rawPass);
                try {
                    return new String(Base64.getEncoder().encode(pbeByteEncryptor.encrypt(bytes)));
                } finally {
                    scramble(bytes);
                }
            }
        };
    }

    byte[] lookupPasswordFromKeyStore() {
        try {
            if (!keystoreProvider.containsAlias(getKeyAliasInKeyStore())) {
                throw new RuntimeException("Keystore: "
                        + keystoreProvider.getResource().path()
                        + " does not"
                        + " contain alias: "
                        + getKeyAliasInKeyStore());
            }
            return keystoreProvider.getSecretKey(getKeyAliasInKeyStore()).getEncoded();
        } catch (IOException e) {
            throw new RuntimeException("Cannot find alias: "
                    + getKeyAliasInKeyStore()
                    + " in "
                    + keystoreProvider.getResource().path());
        }
    }

    @Override
    public PasswordEncodingType getEncodingType() {
        return PasswordEncodingType.ENCRYPT;
    }

    @Override
    public String decode(String encPass) throws UnsupportedOperationException {
        if (pbeStringEncryptor == null) {
            // not initialized
            getStringEncoder();
        }

        return pbeStringEncryptor.decrypt(removePrefix(encPass));
    }

    @Override
    public char[] decodeToCharArray(String encPass) throws UnsupportedOperationException {
        if (pbeByteEncryptor == null) {
            // not initialized
            getCharEncoder();
        }

        byte[] decoded = Base64.getDecoder().decode(removePrefix(encPass).getBytes());
        byte[] bytes = pbeByteEncryptor.decrypt(decoded);
        try {
            return toChars(bytes);
        } finally {
            scramble(bytes);
        }
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return encodePassword(rawPassword.toString(), null);
    }
}
