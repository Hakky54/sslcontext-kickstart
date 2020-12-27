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

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Represents an ordered list of {@link X509ExtendedKeyManager} with most-preferred managers first.
 *
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
 * @author Hakan Altinda
 */
public final class CompositeX509ExtendedKeyManager extends X509ExtendedKeyManager {

    private final List<? extends X509ExtendedKeyManager> keyManagers;

    /**
     * Creates a new {@link CompositeX509ExtendedKeyManager}.
     *
     * @param keyManagers the {@link X509ExtendedKeyManager}, ordered with the most-preferred managers first.
     */
    public CompositeX509ExtendedKeyManager(List<? extends X509ExtendedKeyManager> keyManagers) {
        this.keyManagers = Collections.unmodifiableList(keyManagers);
    }

    /**
     * Chooses the first non-null client alias returned from the delegate
     * {@link X509ExtendedKeyManager}, or {@code null} if there are no matches.
     */
    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        for (X509ExtendedKeyManager keyManager : keyManagers) {
            String alias = keyManager.chooseClientAlias(keyType, issuers, socket);
            if (alias != null) {
                return alias;
            }
        }
        return null;
    }

    /**
     * Chooses the first non-null client alias returned from the delegate
     * {@link X509ExtendedKeyManager}, or {@code null} if there are no matches.
     */
    @Override
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine sslEngine) {
        for (X509ExtendedKeyManager keyManager : keyManagers) {
            String alias = keyManager.chooseEngineClientAlias(keyTypes, issuers, sslEngine);
            if (alias != null) {
                return alias;
            }
        }
        return null;
    }

    /**
     * Chooses the first non-null server alias returned from the delegate
     * {@link X509ExtendedKeyManager}, or {@code null} if there are no matches.
     */
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        for (X509ExtendedKeyManager keyManager : keyManagers) {
            String alias = keyManager.chooseServerAlias(keyType, issuers, socket);
            if (alias != null) {
                return alias;
            }
        }
        return null;
    }

    /**
     * Chooses the first non-null server alias returned from the delegate
     * {@link X509ExtendedKeyManager}, or {@code null} if there are no matches.
     */
    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine sslEngine) {
        for (X509ExtendedKeyManager keyManager : keyManagers) {
            String alias = keyManager.chooseEngineServerAlias(keyType, issuers, sslEngine);
            if (alias != null) {
                return alias;
            }
        }
        return null;
    }

    /**
     * Returns the first non-null private key associated with the
     * given alias, or {@code null} if the alias can't be found.
     */
    @Override
    public PrivateKey getPrivateKey(String alias) {
        for (X509ExtendedKeyManager keyManager : keyManagers) {
            PrivateKey privateKey = keyManager.getPrivateKey(alias);
            if (privateKey != null) {
                return privateKey;
            }
        }
        return null;
    }

    /**
     * Returns the first non-null certificate chain associated with the
     * given alias, or {@code null} if the alias can't be found.
     */
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        for (X509ExtendedKeyManager keyManager : keyManagers) {
            X509Certificate[] chain = keyManager.getCertificateChain(alias);
            if (chain != null && chain.length > 0) {
                return chain;
            }
        }
        return null;
    }

    /**
     * Get all matching aliases for authenticating the client side of a
     * secure socket, or {@code null} if there are no matches.
     */
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        List<String> clientAliases = new ArrayList<>();
        for (X509ExtendedKeyManager keyManager : keyManagers) {
            Optional.ofNullable(keyManager.getClientAliases(keyType, issuers))
                    .ifPresent(aliases -> clientAliases.addAll(Arrays.asList(aliases)));
        }
        return emptyToNull(clientAliases.toArray(new String[]{}));
    }

    /**
     * Get all matching aliases for authenticating the server side of a
     * secure socket, or {@code null} if there are no matches.
     */
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        List<String> serverAliases = new ArrayList<>();
        for (X509ExtendedKeyManager keyManager : keyManagers) {
            Optional.ofNullable(keyManager.getServerAliases(keyType, issuers))
                    .ifPresent(aliases -> serverAliases.addAll(Arrays.asList(aliases)));
        }
        return emptyToNull(serverAliases.toArray(new String[]{}));
    }

    private <T> T[] emptyToNull(T[] arr) {
        return (arr.length == 0) ? null : arr;
    }

    protected int size() {
        return keyManagers.size();
    }

}
