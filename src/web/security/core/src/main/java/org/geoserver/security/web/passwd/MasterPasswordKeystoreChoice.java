package org.geoserver.security.web.passwd;

import java.util.Arrays;
import java.util.List;
import org.apache.wicket.markup.html.form.ChoiceRenderer;
import org.apache.wicket.markup.html.form.DropDownChoice;
import org.apache.wicket.model.IModel;
import org.geoserver.security.KeyStoreProviderJCEKS;
import org.geoserver.security.KeyStoreProviderPKCS12;

public class MasterPasswordKeystoreChoice extends DropDownChoice<String> {

    public MasterPasswordKeystoreChoice(String id) {
        super(id, new MasterPasswordKeystoreModel(), new MasterPasswordKeystoreChoiceRenderer());
    }

    public MasterPasswordKeystoreChoice(String id, IModel<String> model) {
        super(id, model, new MasterPasswordKeystoreModel(), new MasterPasswordKeystoreChoiceRenderer());
    }

    static class MasterPasswordKeystoreModel implements IModel<List<String>> {

        List<String> keystoreTypes;

        MasterPasswordKeystoreModel() {
            keystoreTypes = Arrays.asList(KeyStoreProviderJCEKS.KEYSTORE_TYPE, KeyStoreProviderPKCS12.KEYSTORE_TYPE);
        }

        @Override
        public List<String> getObject() {
            return keystoreTypes;
        }

        @Override
        public void setObject(List<String> object) {
            throw new UnsupportedOperationException();
        }
    }

    static class MasterPasswordKeystoreChoiceRenderer extends ChoiceRenderer<String> {
        @Override
        public Object getDisplayValue(String object) {
            return object;
        }

        @Override
        public String getIdValue(String object, int index) {
            return object;
        }
    }
}
