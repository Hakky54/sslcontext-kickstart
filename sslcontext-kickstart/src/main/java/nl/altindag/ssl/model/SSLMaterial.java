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

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.util.List;

/**
 * <p>
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * </p>
 *
 * @author Hakan Altindag
 */
public final class SSLMaterial {

    private SSLContext sslContext;
    private IdentityMaterial identityMaterial;
    private TrustMaterial trustMaterial;
    private HostnameVerifier hostnameVerifier;
    private SSLParameters sslParameters;
    private List<String> ciphers;
    private List<String> protocols;

    private SSLMaterial() {}

    public SSLContext getSslContext() {
        return sslContext;
    }

    public IdentityMaterial getIdentityMaterial() {
        return identityMaterial;
    }

    public TrustMaterial getTrustMaterial() {
        return trustMaterial;
    }

    public SSLParameters getSslParameters() {
        return sslParameters;
    }

    public HostnameVerifier getHostnameVerifier() {
        return hostnameVerifier;
    }

    public List<String> getCiphers() {
        return ciphers;
    }

    public List<String> getProtocols() {
        return protocols;
    }

    public static class Builder {

        private SSLContext sslContext;
        private IdentityMaterial identityMaterial;
        private TrustMaterial trustMaterial;
        private HostnameVerifier hostnameVerifier;
        private SSLParameters sslParameters;
        private List<String> ciphers;
        private List<String> protocols;

        public Builder withSslContext(SSLContext sslContext) {
            this.sslContext = sslContext;
            return this;
        }

        public Builder withHostnameVerifier(HostnameVerifier hostnameVerifier) {
            this.hostnameVerifier = hostnameVerifier;
            return this;
        }

        public Builder withSslParameters(SSLParameters sslParameters) {
            this.sslParameters = sslParameters;
            return this;
        }

        public Builder withCiphers(List<String> ciphers) {
            this.ciphers = ciphers;
            return this;
        }

        public Builder withProtocols(List<String> protocols) {
            this.protocols = protocols;
            return this;
        }

        public Builder withIdentityMaterial(IdentityMaterial identityMaterial) {
            this.identityMaterial = identityMaterial;
            return this;
        }

        public Builder withTrustMaterial(TrustMaterial trustMaterial) {
            this.trustMaterial = trustMaterial;
            return this;
        }

        public SSLMaterial build() {
            SSLMaterial sslMaterial = new SSLMaterial();
            sslMaterial.sslContext = sslContext;
            sslMaterial.identityMaterial = identityMaterial;
            sslMaterial.trustMaterial = trustMaterial;
            sslMaterial.hostnameVerifier = hostnameVerifier;
            sslMaterial.sslParameters = sslParameters;
            sslMaterial.ciphers = ciphers;
            sslMaterial.protocols = protocols;
            return sslMaterial;
        }
    }

}
