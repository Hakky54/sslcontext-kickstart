/*
 * Copyright 2019 Thunderberry.
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

import javax.net.ssl.SSLEngine;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

import static nl.altindag.ssl.util.internal.ValidationUtils.GENERIC_EXCEPTION_MESSAGE;
import static nl.altindag.ssl.util.internal.ValidationUtils.requireNotBlank;
import static nl.altindag.ssl.util.internal.ValidationUtils.requireNotEmpty;

/**
 * @author Hakan Altindag
 */
public class TrustManagerParameters {

    private final X509Certificate[] chain;
    private final String authType;
    private final Socket socket;
    private final SSLEngine sslEngine;

    public TrustManagerParameters(X509Certificate[] chain, String authType, Socket socket, SSLEngine sslEngine) {
        requireNotEmpty(chain, GENERIC_EXCEPTION_MESSAGE.apply("chain"));
        requireNotBlank(authType, GENERIC_EXCEPTION_MESSAGE.apply("authType"));

        this.chain = Arrays.copyOf(chain, chain.length);
        this.authType = authType;
        this.socket = socket;
        this.sslEngine = sslEngine;
    }

    public X509Certificate[] getChain() {
        return chain;
    }

    public String getAuthType() {
        return authType;
    }

    public Optional<Socket> getSocket() {
        return Optional.ofNullable(socket);
    }

    public Optional<SSLEngine> getSslEngine() {
        return Optional.ofNullable(sslEngine);
    }

}
