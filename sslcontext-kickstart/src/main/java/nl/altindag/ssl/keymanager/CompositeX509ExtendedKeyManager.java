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

package nl.altindag.ssl.keymanager;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Represents an ordered list of {@link X509ExtendedKeyManager} with most-preferred managers first.
 * <p>
 * This is necessary because of the fine-print on {@link javax.net.ssl.SSLContext#init}:
 * Only the first instance of a particular key and/or key manager implementation type in the
 * array is used. (For example, only the first javax.net.ssl.X509KeyManager in the array will be used.)
 * The KeyManager can be build from one or more of any combination provided within the {@link nl.altindag.ssl.util.KeyManagerUtils.KeyManagerBuilder KeyManagerUtils.KeyManagerBuilder}.
 * <br><br>
 * This includes:
 * <pre>
 *     - Any amount of custom KeyManagers
 *     - Any amount of custom Identities
 * </pre>
 *
 * <p>
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.KeyManagerUtils KeyManagerUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 * </p>
 *
 * @see <a href="http://stackoverflow.com/questions/1793979/registering-multiple-keystores-in-jvm">
 *     http://stackoverflow.com/questions/1793979/registering-multiple-keystores-in-jvm
 *     </a>
 * @see <a href="http://codyaray.com/2013/04/java-ssl-with-multiple-keystores">
 *     http://codyaray.com/2013/04/java-ssl-with-multiple-keystores
 *     </a>
 *
 * @author Cody Ray
 * @author Hakan Altindag
 */
public final class CompositeX509ExtendedKeyManager extends X509ExtendedKeyManager {

    private static final Predicate<String> NON_NULL = Objects::nonNull;

    private final List<X509ExtendedKeyManager> keyManagers;
    private final Map<String, List<URI>> preferredAliasToHost;

    /**
     * Creates a new {@link CompositeX509ExtendedKeyManager}.
     *
     * @param keyManagers the {@link X509ExtendedKeyManager}, ordered with the most-preferred managers first.
     */
    public CompositeX509ExtendedKeyManager(List<? extends X509ExtendedKeyManager> keyManagers) {
        this(keyManagers, Collections.emptyMap());
    }

    /**
     * Creates a new {@link CompositeX509ExtendedKeyManager}.
     *
     * @param keyManagers          the {@link X509ExtendedKeyManager}, ordered with the most-preferred managers first.
     * @param preferredAliasToHost the preferred client alias to be used for the given host
     */
    public CompositeX509ExtendedKeyManager(List<? extends X509ExtendedKeyManager> keyManagers,
                                           Map<String, List<URI>> preferredAliasToHost) {
        this.keyManagers = Collections.unmodifiableList(keyManagers);
        this.preferredAliasToHost = new HashMap<>(preferredAliasToHost);
    }

    /**
     * Chooses the first non-null client alias returned from the delegate
     * {@link X509ExtendedKeyManager}, or {@code null} if there are no matches.
     */
    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return chooseClientAlias(
                socket,
                aSocket -> aSocket != null && aSocket.getRemoteSocketAddress() instanceof InetSocketAddress,
                aSocket -> {
                    InetSocketAddress address = (InetSocketAddress) aSocket.getRemoteSocketAddress();
                    return new SimpleImmutableEntry<>(address.getHostName(), address.getPort());
                },
                keyManager -> keyManager.chooseClientAlias(keyType, issuers, socket)
        );
    }

    /**
     * Chooses the first non-null client alias returned from the delegate
     * {@link X509ExtendedKeyManager}, or {@code null} if there are no matches.
     */
    @Override
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine sslEngine) {
        return chooseClientAlias(
                sslEngine,
                Objects::nonNull,
                aSslEngine -> new SimpleImmutableEntry<>(aSslEngine.getPeerHost(), aSslEngine.getPeerPort()),
                keyManager -> keyManager.chooseEngineClientAlias(keyTypes, issuers, sslEngine)
        );
    }

    private <T> String chooseClientAlias(T object,
                                         Predicate<T> predicate,
                                         Function<T, SimpleImmutableEntry<String, Integer>> hostToPortExtractor,
                                         Function<X509ExtendedKeyManager, String> aliasExtractor) {

        Optional<String> preferredClientAlias = getPreferredClientAlias(object, predicate, hostToPortExtractor);
        if (preferredClientAlias.isPresent()) {
            return extractInnerField(aliasExtractor, NON_NULL.and(alias -> preferredClientAlias.get().equals(alias)));
        } else {
            return extractInnerField(aliasExtractor, NON_NULL);
        }
    }

    private <T> Optional<String> getPreferredClientAlias(T object, Predicate<T> predicate, Function<T, SimpleImmutableEntry<String, Integer>> hostToPortExtractor) {
        if (preferredAliasToHost.isEmpty()) {
            return Optional.empty();
        }

        if (predicate.test(object)) {
            SimpleImmutableEntry<String, Integer> hostToPort = hostToPortExtractor.apply(object);
            return getPreferredClientAlias(hostToPort.getKey(), hostToPort.getValue());
        }

        return Optional.empty();
    }

    private Optional<String> getPreferredClientAlias(String peerHost, int peerPort) {
        return preferredAliasToHost.entrySet().stream()
                .filter(entry -> entry.getValue().stream().anyMatch(uri -> uri.getHost().contains(peerHost)))
                .filter(entry -> entry.getValue().stream().anyMatch(uri -> uri.getPort() == peerPort))
                .findFirst()
                .map(Map.Entry::getKey);
    }

    /**
     * Chooses the first non-null server alias returned from the delegate
     * {@link X509ExtendedKeyManager}, or {@code null} if there are no matches.
     */
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return chooseServerAlias(
                socket,
                SSLSocket.class::isInstance,
                aSocket -> ((SSLSocket) aSocket).getHandshakeSession(),
                keyManager -> keyManager.chooseServerAlias(keyType, issuers, socket)
        );
    }

    /**
     * Chooses the first non-null server alias returned from the delegate
     * {@link X509ExtendedKeyManager}, or {@code null} if there are no matches.
     */
    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine sslEngine) {
        return chooseServerAlias(
                sslEngine,
                Objects::nonNull,
                SSLEngine::getHandshakeSession,
                keyManager -> keyManager.chooseEngineServerAlias(keyType, issuers, sslEngine)
        );
    }

    private <T> String chooseServerAlias(T object,
                                         Predicate<T> predicate,
                                         Function<T, SSLSession> sslSessionExtractor,
                                         Function<X509ExtendedKeyManager, String> aliasExtractor) {

        return getPreferredServerAlias(object, predicate, sslSessionExtractor)
                .map(preferredAlias -> extractInnerField(aliasExtractor, NON_NULL.and(preferredAlias::equals)))
                .orElseGet(() -> extractInnerField(aliasExtractor, NON_NULL));
    }

    private <T> Optional<String> getPreferredServerAlias(T object, Predicate<T> predicate, Function<T, SSLSession> sslSessionExtractor) {
        if (preferredAliasToHost.isEmpty()) {
            return Optional.empty();
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

        return Optional.empty();
    }

    private Optional<String> getPreferredServerAlias(Set<String> hostnames) {
        return preferredAliasToHost.entrySet().stream()
                .filter(entry -> entry.getValue().stream().anyMatch(uri -> hostnames.stream().anyMatch(hostname -> uri.getHost().contains(hostname))))
                .findFirst()
                .map(Map.Entry::getKey);
    }

    /**
     * Returns the first non-null private key associated with the
     * given alias, or {@code null} if the alias can't be found.
     */
    @Override
    public PrivateKey getPrivateKey(String alias) {
        return extractInnerField(
                keyManager -> keyManager.getPrivateKey(alias),
                Objects::nonNull
        );
    }

    /**
     * Returns the first non-null certificate chain associated with the
     * given alias, or {@code null} if the alias can't be found.
     */
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return extractInnerField(
                keyManager -> keyManager.getCertificateChain(alias),
                chain -> chain != null && chain.length > 0
        );
    }

    private <T> T extractInnerField(Function<X509ExtendedKeyManager, T> keyManagerMapper, Predicate<T> predicate) {
        return keyManagers.stream()
                .map(keyManagerMapper)
                .filter(predicate)
                .findFirst()
                .orElse(null);
    }

    /**
     * Get all matching aliases for authenticating the client side of a
     * secure socket, or {@code null} if there are no matches.
     */
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return getAliases(keyManager -> keyManager.getClientAliases(keyType, issuers));
    }

    /**
     * Get all matching aliases for authenticating the server side of a
     * secure socket, or {@code null} if there are no matches.
     */
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return getAliases(keyManager -> keyManager.getServerAliases(keyType, issuers));
    }

    private String[] getAliases(Function<X509ExtendedKeyManager, String[]> aliasExtractor) {
        return keyManagers.stream()
                .map(aliasExtractor)
                .filter(Objects::nonNull)
                .flatMap(Arrays::stream)
                .collect(Collectors.collectingAndThen(Collectors.toList(), this::emptyToNull));
    }

    private String[] emptyToNull(List<String> list) {
        return list.isEmpty() ? null : list.toArray(new String[]{});
    }

    public int size() {
        return keyManagers.size();
    }

    public List<X509ExtendedKeyManager> getKeyManagers() {
        return keyManagers;
    }

    @Deprecated
    public Map<String, List<URI>> getPreferredClientAliasToHosts() {
        return preferredAliasToHost;
    }

    public Map<String, List<URI>> getPreferredAliasToHosts() {
        return preferredAliasToHost;
    }

}
