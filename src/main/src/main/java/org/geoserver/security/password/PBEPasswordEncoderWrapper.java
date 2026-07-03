/* (c) 2018 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import java.util.Objects;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Wrapper class for {@link GeoServerPBEByteEncryptor} enabling the class to return the Spring version of
 * PasswordEncoder
 *
 * <p>Used by {@link GeoServerPBEPasswordEncoder}
 *
 * @author vickdw Created on 10/23/18
 */
public class PBEPasswordEncoderWrapper implements PasswordEncoder {

    private GeoServerPBEStringEncryptor encryptor;

    public PBEPasswordEncoderWrapper() {}

    public void setPbeStringEncryptor(GeoServerPBEStringEncryptor encryptor) {
        this.encryptor = encryptor;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword != null) {
            return encryptor.encrypt(rawPassword.toString());
        }
        return null;
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        checkInitialization();
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }
        return Objects.equals(encryptor.decrypt(encodedPassword), rawPassword.toString());
    }

    private void checkInitialization() {
        if (encryptor == null) {
            throw new IllegalStateException("PBE Password encoder not initialized");
        }
    }
}
