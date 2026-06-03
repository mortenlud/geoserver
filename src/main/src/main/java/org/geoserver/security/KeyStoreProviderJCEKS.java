/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security;

/**
 * Class for GeoServer specific key management
 *
 * <p>The type of the keystore is JCEKS and can be used/modified with java tools like "keytool" from the command line.
 *
 * @author mortenlud
 */
public final class KeyStoreProviderJCEKS extends AbstractKeyStoreProvider {

    public static final String KEYSTORE_TYPE = "JCEKS";
    private static final String FILE_NAME = "geoserver.jceks";
    private static final String KEY_ALGORITHM = "PBE";

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
