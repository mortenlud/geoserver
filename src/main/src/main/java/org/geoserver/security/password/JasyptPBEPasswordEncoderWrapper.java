/* (c) 2018 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import java.util.Objects;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.springframework.dao.DataAccessException;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Wrapper class for jasypt PBEPasswordEncoder enabling the class to return the Spring 5.1 version of PasswordEncoder
 *
 * <p>Used by {@link GeoServerPBEPasswordEncoder}
 *
 * @author vickdw Created on 10/23/18
 */
public class JasyptPBEPasswordEncoderWrapper extends AbstractGeoserverPasswordEncoder implements PasswordEncoder {
    private LegacyPBEEncryptor pbeStringEncryptor = null;

    public JasyptPBEPasswordEncoderWrapper() {}

    /** Creates the encoder instance used when source is a string. */
    @Override
    protected PasswordEncoder createStringEncoder() {
        return new PasswordEncoder() {

            @Override
            public boolean matches(CharSequence encPass, String rawPass) throws DataAccessException {
                return false;
            }

            @Override
            public String encode(CharSequence rawPass) throws DataAccessException {
                return "";
            }
        };
    }

    /** Creates the encoder instance used when source is a char array. */
    @Override
    protected CharArrayPasswordEncoder createCharEncoder() {
        return new CharArrayPasswordEncoder() {

            @Override
            public boolean isPasswordValid(String encPass, char[] rawPass, Object salt) {
                return false;
            }

            @Override
            public String encodePassword(char[] rawPass, Object salt) {
                return "";
            }
        };
    }

    void setPbeStringEncryptor(LegacyPBEEncryptor pbeStringEncryptor) {
        this.pbeStringEncryptor = pbeStringEncryptor;
    }

    @Override
    public String encodePassword(String rawPass, Object salt) {
        this.checkInitialization();
        return this.pbeStringEncryptor.encrypt(rawPass);
    }

    @Override
    public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
        this.checkInitialization();

        return Objects.equals(this.pbeStringEncryptor.decrypt(encPass), rawPass);
    }

    @Override
    public PasswordEncodingType getEncodingType() {
        return PasswordEncodingType.ENCRYPT;
    }

    private synchronized void checkInitialization() {
        if (this.pbeStringEncryptor == null) {
            throw new EncryptionInitializationException(
                    "PBE Password encoder not initialized: PBE string encryptor is null");
        }
    }

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword != null) {
            return encodePassword(rawPassword.toString(), null);
        }
        return null;
    }
}
