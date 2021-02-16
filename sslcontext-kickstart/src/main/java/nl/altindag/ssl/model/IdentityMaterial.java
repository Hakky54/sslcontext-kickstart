/*
 * Copyright 2019-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.altindag.ssl.model;

import javax.net.ssl.X509ExtendedKeyManager;
import java.net.URI;
import java.util.List;
import java.util.Map;

/**
 * <p>
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * </p>
 *
 * @author Hakan Altindag
 */
public final class IdentityMaterial {

    private X509ExtendedKeyManager keyManager;
    private List<KeyStoreHolder> identities;
    private Map<String, List<URI>> preferredClientAliasToHost;

    private IdentityMaterial() {}

    public X509ExtendedKeyManager getKeyManager() {
        return keyManager;
    }

    public List<KeyStoreHolder> getIdentities() {
        return identities;
    }

    public Map<String, List<URI>> getPreferredClientAliasToHost() {
        return preferredClientAliasToHost;
    }

    public static class Builder {

        private X509ExtendedKeyManager keyManager;
        private List<KeyStoreHolder> identities;
        private Map<String, List<URI>> preferredClientAliasToHost;

        public Builder withKeyManager(X509ExtendedKeyManager keyManager) {
            this.keyManager = keyManager;
            return this;
        }

        public Builder withIdentities(List<KeyStoreHolder> identities) {
            this.identities = identities;
            return this;
        }

        public Builder withPreferredClientAliasToHost(Map<String, List<URI>> preferredClientAliasToHost) {
            this.preferredClientAliasToHost = preferredClientAliasToHost;
            return this;
        }

        public IdentityMaterial build() {
            IdentityMaterial identityMaterial = new IdentityMaterial();
            identityMaterial.keyManager = keyManager;
            identityMaterial.identities = identities;
            identityMaterial.preferredClientAliasToHost = preferredClientAliasToHost;
            return identityMaterial;
        }
    }

}
