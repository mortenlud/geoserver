/* (c) 2026 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.geoserver.security.password.MasterPasswordConfig;
import org.geoserver.security.password.RandomPasswordProvider;
import org.geoserver.test.GeoServerSystemTestSupport;
import org.junit.Test;

public class KeyStoreProviderPKCS12Test extends GeoServerSystemTestSupport {

    @Test
    public void testPKCS12KeyStoreProvider() throws Exception {

        MasterPasswordConfig masterPasswordConfig = getSecurityManager().getMasterPasswordConfig();
        masterPasswordConfig.setKeystoreType(KeyStoreProviderPKCS12.KEYSTORE_TYPE);
        getSecurityManager().init(masterPasswordConfig);

        KeyStoreProvider ksp = getSecurityManager().lookupKeyStoreProvider();

        ksp.removeKey(AbstractKeyStoreProvider.CONFIGPASSWORDKEY);
        ksp.removeKey(ksp.aliasForGroupService("default"));
        ksp.storeKeyStore();
        ksp.reloadKeyStore();

        assertFalse(ksp.hasConfigPasswordKey());
        assertFalse(ksp.hasUserGroupKey("default"));

        ksp.setSecretKey(AbstractKeyStoreProvider.CONFIGPASSWORDKEY, "configKey".toCharArray());
        ksp.storeKeyStore();

        assertTrue(ksp.hasConfigPasswordKey());
        assertEquals("configKey", new String(ksp.getConfigPasswordKey()));
        assertFalse(ksp.hasUserGroupKey("default"));

        RandomPasswordProvider rpp = getSecurityManager().getRandomPassworddProvider();
        char[] urlKey = rpp.getRandomPasswordWithDefaultLength();
        // System.out.printf("Random password with length %d : %s\n",urlKey.length,new
        // String(urlKey));
        char[] urlKey2 = rpp.getRandomPasswordWithDefaultLength();
        // System.out.printf("Random password with length %d : %s\n",urlKey2.length,new
        // String(urlKey2));
        assertThat(urlKey, not(equalTo(urlKey2)));

        ksp.setSecretKey(
                AbstractKeyStoreProvider.USERGROUP_PREFIX + "default" + AbstractKeyStoreProvider.USERGROUP_POSTFIX,
                "defaultKey".toCharArray());

        ksp.storeKeyStore();

        assertTrue(ksp.hasConfigPasswordKey());
        assertEquals("configKey", new String(ksp.getConfigPasswordKey()));
        assertTrue(ksp.hasUserGroupKey("default"));
        assertEquals("defaultKey", new String(ksp.getUserGroupKey("default")));

        assertTrue(ksp.isKeyStorePassword(getSecurityManager().getMasterPassword()));
        assertFalse(ksp.isKeyStorePassword("blabla".toCharArray()));
    }
}
