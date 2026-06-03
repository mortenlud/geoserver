/* (c) 2014 Open Source Geospatial Foundation - all rights reserved
 * (c) 2001 - 2013 OpenPlans
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import java.io.Serial;
import org.apache.commons.lang3.SerializationUtils;
import org.geoserver.platform.GeoServerEnvironment;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.KeyStoreProviderJCEKS;
import org.geoserver.security.config.SecurityConfig;

/**
 * Configuration object for the GeoServer master password.
 *
 * @author Justin Deoliveira, OpenGeo
 */
public class MasterPasswordConfig implements SecurityConfig {

    /** serialVersionUID */
    @Serial
    private static final long serialVersionUID = 1L;

    String providerName;

    String keystoreType;

    public MasterPasswordConfig() {}

    public MasterPasswordConfig(MasterPasswordConfig other) {
        this.providerName = other.getProviderName();
        this.keystoreType = other.getKeystoreType();
    }

    /** The name of the master password provider. */
    public String getProviderName() {
        return providerName;
    }

    /** Sets the name of the master password provider. */
    public void setProviderName(String providerName) {
        this.providerName = providerName;
    }

    /** The keystoreType to use for storing master password */
    public String getKeystoreType() {
        return keystoreType == null ? KeyStoreProviderJCEKS.KEYSTORE_TYPE : keystoreType;
    }

    /** Sets the keystoreType */
    public void setKeystoreType(String keystoreType) {
        this.keystoreType = keystoreType;
    }

    @Override
    public SecurityConfig clone(boolean allowEnvParametrization) {

        final GeoServerEnvironment gsEnvironment = GeoServerExtensions.bean(GeoServerEnvironment.class);

        MasterPasswordConfig target = SerializationUtils.clone(this);

        if (target != null) {
            if (allowEnvParametrization && gsEnvironment != null && GeoServerEnvironment.allowEnvParametrization()) {
                target.setProviderName((String) gsEnvironment.resolveValue(providerName));
                target.setKeystoreType((String) gsEnvironment.resolveValue(keystoreType));
            }
        }

        return target;
    }
}
