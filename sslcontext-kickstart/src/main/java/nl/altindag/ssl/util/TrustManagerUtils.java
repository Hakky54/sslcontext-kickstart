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
package nl.altindag.ssl.util;

import nl.altindag.ssl.exception.GenericTrustManagerException;
import nl.altindag.ssl.trustmanager.CertificateCapturingX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.ChainAndAuthTypeValidator;
import nl.altindag.ssl.trustmanager.ChainAndAuthTypeWithSSLEngineValidator;
import nl.altindag.ssl.trustmanager.ChainAndAuthTypeWithSocketValidator;
import nl.altindag.ssl.trustmanager.CompositeX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.DummyX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.EnhanceableX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.HotSwappableX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.TrustManagerFactoryWrapper;
import nl.altindag.ssl.trustmanager.UnsafeX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.X509TrustManagerWrapper;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static nl.altindag.ssl.util.ValidationUtils.requireNotEmpty;

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

    public static X509ExtendedTrustManager createTrustManager(KeyStore... trustStores) {
        return Arrays.stream(trustStores)
                .map(TrustManagerUtils::createTrustManager)
                .collect(Collectors.collectingAndThen(Collectors.toList(), TrustManagerUtils::combine));
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

    public static X509ExtendedTrustManager createTrustManager(ManagerFactoryParameters... managerFactoryParameters) {
        return Arrays.stream(managerFactoryParameters)
                .map(TrustManagerUtils::createTrustManager)
                .collect(Collectors.collectingAndThen(Collectors.toList(), TrustManagerUtils::combine));
    }

    public static X509ExtendedTrustManager createTrustManager(ManagerFactoryParameters managerFactoryParameters) {
        return createTrustManager(managerFactoryParameters, TrustManagerFactory.getDefaultAlgorithm());
    }

    public static X509ExtendedTrustManager createTrustManager(ManagerFactoryParameters managerFactoryParameters, String trustManagerFactoryAlgorithm) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm);
            return createTrustManager(managerFactoryParameters, trustManagerFactory);
        } catch (NoSuchAlgorithmException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createTrustManager(ManagerFactoryParameters managerFactoryParameters, String trustManagerFactoryAlgorithm, String securityProviderName) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm, securityProviderName);
            return createTrustManager(managerFactoryParameters, trustManagerFactory);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createTrustManager(ManagerFactoryParameters managerFactoryParameters, String trustManagerFactoryAlgorithm, Provider securityProvider) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm, securityProvider);
            return createTrustManager(managerFactoryParameters, trustManagerFactory);
        } catch (NoSuchAlgorithmException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createTrustManager(ManagerFactoryParameters managerFactoryParameters, TrustManagerFactory trustManagerFactory) {
        try {
            trustManagerFactory.init(managerFactoryParameters);
            return TrustManagerUtils.getTrustManager(trustManagerFactory);
        } catch (InvalidAlgorithmParameterException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createUnsafeTrustManager() {
        return UnsafeX509ExtendedTrustManager.getInstance();
    }

    public static X509ExtendedTrustManager createDummyTrustManager() {
        return DummyX509ExtendedTrustManager.getInstance();
    }

    public static X509ExtendedTrustManager createCertificateCapturingTrustManager(List<X509Certificate> certificatesCollector) {
        return createCertificateCapturingTrustManager(TrustManagerUtils.createUnsafeTrustManager(), certificatesCollector);
    }

    public static X509ExtendedTrustManager createCertificateCapturingTrustManager(X509TrustManager baseTrustManager, List<X509Certificate> certificatesCollector) {
        return new CertificateCapturingX509ExtendedTrustManager(wrapIfNeeded(baseTrustManager), certificatesCollector);
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
                .collect(Collectors.collectingAndThen(Collectors.toList(), TrustManagerUtils::combine));
    }

    /**
     * Wraps the given TrustManager into an instance of a Hot Swappable TrustManager.
     * This type of TrustManager has the capability of swapping in and out different TrustManagers at runtime.
     *
     * @param trustManager  To be wrapped TrustManager
     * @return              Swappable TrustManager
     */
    public static X509ExtendedTrustManager createSwappableTrustManager(X509TrustManager trustManager) {
        return new HotSwappableX509ExtendedTrustManager(TrustManagerUtils.wrapIfNeeded(trustManager));
    }

    /**
     * Swaps the internal TrustManager instance with the given trustManager object.
     * The baseTrustManager should be an instance of {@link HotSwappableX509ExtendedTrustManager}
     * and can be created with {@link TrustManagerUtils#createSwappableTrustManager(X509TrustManager)}
     *
     * @param baseTrustManager              an instance of {@link HotSwappableX509ExtendedTrustManager}
     * @param newTrustManager               to be injected instance of a TrustManager
     * @throws GenericTrustManagerException if {@code baseTrustManager} is not instance of {@link HotSwappableX509ExtendedTrustManager}
     */
    public static void swapTrustManager(X509TrustManager baseTrustManager, X509TrustManager newTrustManager) {
        if (newTrustManager instanceof HotSwappableX509ExtendedTrustManager) {
            throw new GenericTrustManagerException(
                    String.format("The newTrustManager should not be an instance of [%s]", HotSwappableX509ExtendedTrustManager.class.getName())
            );
        }

        if (baseTrustManager instanceof HotSwappableX509ExtendedTrustManager) {
            ((HotSwappableX509ExtendedTrustManager) baseTrustManager).setTrustManager(TrustManagerUtils.wrapIfNeeded(newTrustManager));
        } else {
            throw new GenericTrustManagerException(
                    String.format("The baseTrustManager is from the instance of [%s] and should be an instance of [%s].",
                            baseTrustManager.getClass().getName(),
                            HotSwappableX509ExtendedTrustManager.class.getName())
            );
        }
    }

    public static X509ExtendedTrustManager createEnhanceableTrustManager(
            X509ExtendedTrustManager trustManager,
            ChainAndAuthTypeValidator chainAndAuthTypeValidator,
            ChainAndAuthTypeWithSocketValidator chainAndAuthTypeWithSocketValidator,
            ChainAndAuthTypeWithSSLEngineValidator chainAndAuthTypeWithSSLEngineValidator) {

        return new EnhanceableX509ExtendedTrustManager(
                trustManager,
                chainAndAuthTypeValidator,
                chainAndAuthTypeWithSocketValidator,
                chainAndAuthTypeWithSSLEngineValidator
        );
    }

    private static List<X509ExtendedTrustManager> unwrapIfPossible(X509ExtendedTrustManager trustManager) {
        List<X509ExtendedTrustManager> trustManagers = new ArrayList<>();
        if (trustManager instanceof CompositeX509ExtendedTrustManager) {
            for (X509ExtendedTrustManager innerTrustManager : ((CompositeX509ExtendedTrustManager) trustManager).getTrustManagers()) {
                List<X509ExtendedTrustManager> unwrappedTrustManagers = TrustManagerUtils.unwrapIfPossible(innerTrustManager);
                trustManagers.addAll(unwrappedTrustManagers);
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
        private boolean swappableTrustManagerEnabled = false;

        private ChainAndAuthTypeValidator chainAndAuthTypeValidator;
        private ChainAndAuthTypeWithSocketValidator chainAndAuthTypeWithSocketValidator;
        private ChainAndAuthTypeWithSSLEngineValidator chainAndAuthTypeWithSSLEngineValidator;

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

        public TrustManagerBuilder withSwappableTrustManager(boolean swappableTrustManagerEnabled) {
            this.swappableTrustManagerEnabled = swappableTrustManagerEnabled;
            return this;
        }

        public TrustManagerBuilder withTrustEnhancer(ChainAndAuthTypeValidator validator) {
            this.chainAndAuthTypeValidator = validator;
            return this;
        }

        public TrustManagerBuilder withTrustEnhancer(ChainAndAuthTypeWithSocketValidator validator) {
            this.chainAndAuthTypeWithSocketValidator = validator;
            return this;
        }

        public TrustManagerBuilder withTrustEnhancer(ChainAndAuthTypeWithSSLEngineValidator validator) {
            this.chainAndAuthTypeWithSSLEngineValidator = validator;
            return this;
        }

        public X509ExtendedTrustManager build() {
            requireNotEmpty(trustManagers, () -> new GenericTrustManagerException(EMPTY_TRUST_MANAGER_EXCEPTION));

            X509ExtendedTrustManager trustManager;
            if (trustManagers.size() == 1) {
                trustManager = trustManagers.get(0);
            } else {
                trustManager = trustManagers.stream()
                        .map(TrustManagerUtils::unwrapIfPossible)
                        .flatMap(Collection::stream)
                        .collect(Collectors.collectingAndThen(Collectors.toList(), CompositeX509ExtendedTrustManager::new));
            }

            if (chainAndAuthTypeValidator != null
                    || chainAndAuthTypeWithSocketValidator != null
                    || chainAndAuthTypeWithSSLEngineValidator != null) {
                trustManager = TrustManagerUtils.createEnhanceableTrustManager(
                        trustManager,
                        chainAndAuthTypeValidator,
                        chainAndAuthTypeWithSocketValidator,
                        chainAndAuthTypeWithSSLEngineValidator
                );
            }

            if (swappableTrustManagerEnabled) {
                trustManager = TrustManagerUtils.createSwappableTrustManager(trustManager);
            }

            return trustManager;
        }
    }

}
