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
package nl.altindag.ssl.util;

import javax.net.ssl.SSLParameters;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * @author Hakan Altindag
 */
public final class SSLParametersUtils {

    private SSLParametersUtils() {
    }

    public static SSLParameters copy(SSLParameters source) {
        SSLParameters target = new SSLParameters();
        target.setProtocols(source.getProtocols());
        target.setCipherSuites(source.getCipherSuites());
        if (source.getWantClientAuth()) {
            target.setWantClientAuth(true);
        }

        if (source.getNeedClientAuth()) {
            target.setNeedClientAuth(true);
        }
        return target;
    }

    public static SSLParameters merge(SSLParameters baseSslParameters, SSLParameters alternativeSslParameters) {
        return merge(baseSslParameters, alternativeSslParameters, Collections.emptyList(), Collections.emptyList());
    }

    public static SSLParameters merge(SSLParameters baseSslParameters, SSLParameters alternativeSslParameters, List<String> excludedCiphers, List<String> excludedProtocols) {
        SSLParameters target = new SSLParameters();

        String[] ciphers = Optional.ofNullable(baseSslParameters.getCipherSuites())
                .filter(array -> array.length != 0)
                .orElseGet(alternativeSslParameters::getCipherSuites);
        String[] protocols = Optional.ofNullable(baseSslParameters.getProtocols())
                .filter(array -> array.length != 0)
                .orElseGet(alternativeSslParameters::getProtocols);

        if (!excludedCiphers.isEmpty()) {
            ciphers = Arrays.stream(ciphers)
                    .filter(cipher -> !excludedCiphers.contains(cipher))
                    .toArray(String[]::new);

            if (ciphers.length == 0) {
                ciphers = alternativeSslParameters.getCipherSuites();
            }
        }

        if (!excludedProtocols.isEmpty()) {
            protocols = Arrays.stream(protocols)
                    .filter(cipher -> !excludedProtocols.contains(cipher))
                    .toArray(String[]::new);

            if (protocols.length == 0) {
                protocols = alternativeSslParameters.getProtocols();
            }
        }

        target.setCipherSuites(ciphers);
        target.setProtocols(protocols);

        boolean wantClientAuth = baseSslParameters.getWantClientAuth() ? baseSslParameters.getWantClientAuth() : alternativeSslParameters.getWantClientAuth();
        if (wantClientAuth) {
            target.setWantClientAuth(true);
        }

        boolean needClientAuth = baseSslParameters.getNeedClientAuth() ? baseSslParameters.getNeedClientAuth() : alternativeSslParameters.getNeedClientAuth();
        if (needClientAuth) {
            target.setNeedClientAuth(true);
        }

        return target;
    }

}
