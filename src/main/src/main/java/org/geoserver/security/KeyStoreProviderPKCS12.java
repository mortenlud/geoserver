/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security;

/**
 * Class for GeoServer specific key management
 *
 * <p>The type of the keystore is PKCS12 and can be used/modified with java tools like "keytool" from the command line.
 *
 * @author mortenlud
 */
public final class KeyStoreProviderPKCS12 extends AbstractKeyStoreProvider {

    public static final String KEYSTORE_TYPE = "PKCS12";
    private static final String FILE_NAME = "geoserver.pkcs12";
    private static final String KEY_ALGORITHM = "AES";

    @Override
    String getKeyStoreType() {
        return KEYSTORE_TYPE;
    }

    @Override
    String getFileName() {
        return FILE_NAME;
    }

    @Override
    String getKeyAlgorithm() {
        return KEY_ALGORITHM;
    }
}
