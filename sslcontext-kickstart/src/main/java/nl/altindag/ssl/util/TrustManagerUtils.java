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

package nl.altindag.ssl.util;

import nl.altindag.ssl.exception.GenericTrustManagerException;
import nl.altindag.ssl.model.KeyStoreHolder;
import nl.altindag.ssl.trustmanager.CompositeX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.TrustManagerFactoryWrapper;
import nl.altindag.ssl.trustmanager.UnsafeX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.X509TrustManagerWrapper;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;

/**
 * @author Hakan Altindag
 */
public final class TrustManagerUtils {

    private TrustManagerUtils() {}

    public static X509ExtendedTrustManager combine(X509TrustManager... trustManagers) {
        return combine(Arrays.asList(trustManagers));
    }

    public static X509ExtendedTrustManager combine(List<? extends X509TrustManager> trustManagers) {
        return TrustManagerUtils.trustManagerBuilder()
                .withTrustManagers(trustManagers)
                .build();
    }

    public static <T extends X509TrustManager> X509ExtendedTrustManager[] toArray(T trustManager) {
        return new X509ExtendedTrustManager[]{TrustManagerUtils.wrapIfNeeded(trustManager)};
    }

    public static X509ExtendedTrustManager createTrustManagerWithJdkTrustedCertificates() {
        return createTrustManager((KeyStore) null);
    }

    public static Optional<X509ExtendedTrustManager> createTrustManagerWithSystemTrustedCertificates() {
        List<KeyStore> trustStores = KeyStoreUtils.loadSystemKeyStores();
        if (trustStores.isEmpty()) {
            return Optional.empty();
        }

        X509ExtendedTrustManager trustManager = createTrustManager(trustStores.toArray(new KeyStore[]{}));
        return Optional.of(trustManager);
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStoreHolder... trustStoreHolders) {
        return Arrays.stream(trustStoreHolders)
                .map(KeyStoreHolder::getKeyStore)
                .map(TrustManagerUtils::createTrustManager)
                .collect(collectingAndThen(toList(), TrustManagerUtils::combine));
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore... trustStores) {
        return Arrays.stream(trustStores)
                .map(TrustManagerUtils::createTrustManager)
                .collect(collectingAndThen(toList(), TrustManagerUtils::combine));
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore trustStore) {
        return createTrustManager(trustStore, TrustManagerFactory.getDefaultAlgorithm());
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore trustStore, String trustManagerFactoryAlgorithm) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm);
            return createTrustManager(trustStore, trustManagerFactory);
        } catch (NoSuchAlgorithmException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore trustStore, String trustManagerFactoryAlgorithm, String securityProviderName) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm, securityProviderName);
            return createTrustManager(trustStore, trustManagerFactory);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore trustStore, String trustManagerFactoryAlgorithm, Provider securityProvider) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm, securityProvider);
            return createTrustManager(trustStore, trustManagerFactory);
        } catch (NoSuchAlgorithmException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore trustStore, TrustManagerFactory trustManagerFactory) {
        try {
            trustManagerFactory.init(trustStore);
            return TrustManagerUtils.getTrustManager(trustManagerFactory);
        } catch (KeyStoreException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createUnsafeTrustManager() {
        return UnsafeX509ExtendedTrustManager.getInstance();
    }

    public static X509ExtendedTrustManager wrapIfNeeded(X509TrustManager trustManager) {
        if (trustManager instanceof X509ExtendedTrustManager) {
            return (X509ExtendedTrustManager) trustManager;
        } else {
            return new X509TrustManagerWrapper(trustManager);
        }
    }

    public static TrustManagerFactory createTrustManagerFactory(TrustManager trustManager) {
        return new TrustManagerFactoryWrapper(trustManager);
    }

    public static <T extends TrustManagerFactory> X509ExtendedTrustManager getTrustManager(T trustManagerFactory) {
        return Arrays.stream(trustManagerFactory.getTrustManagers())
                .filter(X509TrustManager.class::isInstance)
                .map(X509TrustManager.class::cast)
                .map(TrustManagerUtils::wrapIfNeeded)
                .collect(collectingAndThen(toList(), TrustManagerUtils::combine));
    }

    private static List<X509ExtendedTrustManager> unwrapIfPossible(X509ExtendedTrustManager trustManager) {
        List<X509ExtendedTrustManager> trustManagers = new ArrayList<>();
        if (trustManager instanceof CompositeX509ExtendedTrustManager) {
            for (X509ExtendedTrustManager innerTrustManager : ((CompositeX509ExtendedTrustManager) trustManager).getTrustManagers()) {
                trustManagers.addAll(TrustManagerUtils.unwrapIfPossible(innerTrustManager));
            }
        } else {
            trustManagers.add(trustManager);
        }

        return trustManagers;
    }

    public static TrustManagerBuilder trustManagerBuilder() {
        return new TrustManagerBuilder();
    }

    public static final class TrustManagerBuilder {

        private static final String EMPTY_TRUST_MANAGER_EXCEPTION = "Input does not contain TrustManager";

        private TrustManagerBuilder() {}

        private final List<X509ExtendedTrustManager> trustManagers = new ArrayList<>();

        public <T extends X509TrustManager> TrustManagerBuilder withTrustManagers(T... trustManagers) {
            for (T trustManager : trustManagers) {
                withTrustManager(trustManager);
            }
            return this;
        }

        public <T extends X509TrustManager> TrustManagerBuilder withTrustManagers(List<T> trustManagers) {
            for (X509TrustManager trustManager : trustManagers) {
                withTrustManager(trustManager);
            }
            return this;
        }

        public <T extends X509TrustManager> TrustManagerBuilder withTrustManager(T trustManager) {
            this.trustManagers.add(TrustManagerUtils.wrapIfNeeded(trustManager));
            return this;
        }

        public <T extends KeyStore> TrustManagerBuilder withTrustStores(T... trustStores) {
            return withTrustStores(Arrays.asList(trustStores));
        }

        public TrustManagerBuilder withTrustStores(List<? extends KeyStore> trustStores) {
            for (KeyStore trustStore : trustStores) {
                this.trustManagers.add(TrustManagerUtils.createTrustManager(trustStore));
            }
            return this;
        }

        public <T extends KeyStore> TrustManagerBuilder withTrustStore(T trustStore) {
            this.trustManagers.add(TrustManagerUtils.createTrustManager(trustStore));
            return this;
        }

        public <T extends KeyStore> TrustManagerBuilder withTrustStore(T trustStore, String trustManagerAlgorithm) {
            this.trustManagers.add(TrustManagerUtils.createTrustManager(trustStore, trustManagerAlgorithm));
            return this;
        }

        public X509ExtendedTrustManager build() {
            if (trustManagers.isEmpty()) {
                throw new GenericTrustManagerException(EMPTY_TRUST_MANAGER_EXCEPTION);
            }

            if (trustManagers.size() == 1) {
                return trustManagers.get(0);
            }

            return trustManagers.stream()
                    .map(TrustManagerUtils::unwrapIfPossible)
                    .flatMap(Collection::stream)
                    .collect(Collectors.collectingAndThen(toList(), CompositeX509ExtendedTrustManager::new));
        }

    }

}
