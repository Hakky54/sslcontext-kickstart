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
package nl.altindag.ssl.keymanager;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.util.AbstractMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.Set;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
interface RoutableX509ExtendedKeyManager extends CombinableX509ExtendedKeyManager, X509KeyManager {

    Predicate<String> NON_NULL = Objects::nonNull;

    Map<String, List<URI>> getIdentityRoute();

    default <T> String chooseClientAlias(T object,
                                         Predicate<T> predicate,
                                         Function<T, Entry<String, Integer>> hostToPortExtractor,
                                         Function<X509ExtendedKeyManager, String> aliasExtractor) {

        return chooseAlias(() -> getPreferredClientAlias(object, predicate, hostToPortExtractor), aliasExtractor);
    }

    default <T> String getPreferredClientAlias(T object, Predicate<T> predicate, Function<T, Entry<String, Integer>> hostToPortExtractor) {
        if (getIdentityRoute().isEmpty()) {
            return null;
        }

        if (predicate.test(object)) {
            Entry<String, Integer> hostToPort = hostToPortExtractor.apply(object);
            return getPreferredClientAlias(hostToPort.getKey(), hostToPort.getValue());
        }

        return null;
    }

    default String getPreferredClientAlias(String peerHost, int peerPort) {
        return getIdentityRoute().entrySet().stream()
                .filter(entry -> entry.getValue().stream().anyMatch(uri -> uri.getHost().contains(peerHost)))
                .filter(entry -> entry.getValue().stream().anyMatch(uri -> uri.getPort() == peerPort))
                .findFirst()
                .map(Entry::getKey)
                .orElse(null);
    }

    default <T> String chooseServerAlias(T object,
                                         Predicate<T> predicate,
                                         Function<T, SSLSession> sslSessionExtractor,
                                         Function<X509ExtendedKeyManager, String> aliasExtractor) {

        return chooseAlias(() -> getPreferredServerAlias(object, predicate, sslSessionExtractor), aliasExtractor);
    }

    default <T> String getPreferredServerAlias(T object, Predicate<T> predicate, Function<T, SSLSession> sslSessionExtractor) {
        if (getIdentityRoute().isEmpty()) {
            return null;
        }

        if (predicate.test(object)) {
            SSLSession sslSession = sslSessionExtractor.apply(object);
            if (sslSession instanceof ExtendedSSLSession) {
                List<SNIServerName> requestedServerNames = ((ExtendedSSLSession) sslSession).getRequestedServerNames();
                Set<String> hostnames = requestedServerNames.stream()
                        .map(sniServerName -> new String(sniServerName.getEncoded()))
                        .collect(Collectors.toSet());

                return getPreferredServerAlias(hostnames);
            }
        }

        return null;
    }

    default String getPreferredServerAlias(Set<String> hostnames) {
        return getIdentityRoute().entrySet().stream()
                .filter(entry -> entry.getValue().stream().anyMatch(uri -> hostnames.stream().anyMatch(hostname -> uri.getHost().contains(hostname))))
                .findFirst()
                .map(Entry::getKey)
                .orElse(null);
    }

    default String chooseAlias(Supplier<String> preferredAliasSupplier, Function<X509ExtendedKeyManager, String> aliasExtractor) {
        String preferredAlias = preferredAliasSupplier.get();

        if (preferredAlias != null) {
            return extractInnerField(aliasExtractor, NON_NULL.and(preferredAlias::equals));
        } else {
            return extractInnerField(aliasExtractor, NON_NULL);
        }
    }

    default boolean containsInetSocketAddress(Socket socket) {
        return socket != null && socket.getRemoteSocketAddress() instanceof InetSocketAddress;
    }

    default Entry<String, Integer> extractHostAndPort(Socket socket) {
        InetSocketAddress address = (InetSocketAddress) socket.getRemoteSocketAddress();
        return new AbstractMap.SimpleImmutableEntry<>(address.getHostName(), address.getPort());
    }

    default Entry<String, Integer> extractHostAndPort(SSLEngine sslEngine) {
        return new AbstractMap.SimpleImmutableEntry<>(sslEngine.getPeerHost(), sslEngine.getPeerPort());
    }

}
