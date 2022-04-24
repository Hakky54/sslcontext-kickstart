/*
 * Copyright 2019-2022 the original author or authors.
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
package nl.altindag.ssl.trustmanager;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public final class EnhanceableX509ExtendedTrustManager extends DelegatingX509ExtendedTrustManager {

    private final ChainAndAuthTypeValidator chainAndAuthTypeValidator;
    private final ChainAndAuthTypeWithSocketValidator chainAndAuthTypeWithSocketValidator;
    private final ChainAndAuthTypeWithSSLEngineValidator chainAndAuthTypeWithSSLEngineValidator;

    public EnhanceableX509ExtendedTrustManager(
            X509ExtendedTrustManager trustManager,
            ChainAndAuthTypeValidator chainAndAuthTypeValidator,
            ChainAndAuthTypeWithSocketValidator chainAndAuthTypeWithSocketValidator,
            ChainAndAuthTypeWithSSLEngineValidator chainAndAuthTypeWithSSLEngineValidator) {

        super(trustManager);
        this.chainAndAuthTypeValidator = chainAndAuthTypeValidator;
        this.chainAndAuthTypeWithSocketValidator = chainAndAuthTypeWithSocketValidator;
        this.chainAndAuthTypeWithSSLEngineValidator = chainAndAuthTypeWithSSLEngineValidator;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chainAndAuthTypeValidator != null && chainAndAuthTypeValidator.test(chain, authType)) {
            return;
        }
        super.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        if (chainAndAuthTypeWithSocketValidator != null && chainAndAuthTypeWithSocketValidator.test(chain, authType, socket)) {
            return;
        }
        super.checkClientTrusted(chain, authType, socket);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        if (chainAndAuthTypeWithSSLEngineValidator != null && chainAndAuthTypeWithSSLEngineValidator.test(chain, authType, sslEngine)) {
            return;
        }
        super.checkClientTrusted(chain, authType, sslEngine);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chainAndAuthTypeValidator != null && chainAndAuthTypeValidator.test(chain, authType)) {
            return;
        }
        super.checkServerTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        if (chainAndAuthTypeWithSocketValidator != null && chainAndAuthTypeWithSocketValidator.test(chain, authType, socket)) {
            return;
        }
        super.checkServerTrusted(chain, authType, socket);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        if (chainAndAuthTypeWithSSLEngineValidator != null && chainAndAuthTypeWithSSLEngineValidator.test(chain, authType, sslEngine)) {
            return;
        }
        super.checkServerTrusted(chain, authType, sslEngine);
    }

}
