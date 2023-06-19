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

import nl.altindag.ssl.exception.GenericKeyStoreException;
import nl.altindag.ssl.util.internal.CollectorsUtils;
import nl.altindag.ssl.util.internal.IOUtils;
import nl.altindag.ssl.util.internal.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import static nl.altindag.ssl.util.internal.ValidationUtils.requireNotEmpty;
import static nl.altindag.ssl.util.internal.ValidationUtils.requireNotNull;

/**
 * @author Hakan Altindag
 */
public final class KeyStoreUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreUtils.class);

    public static final String DUMMY_PASSWORD = "dummy-password";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String EMPTY_INPUT_STREAM_EXCEPTION_MESSAGE = "Failed to load the keystore from the provided InputStream because it is null";
    private static final UnaryOperator<String> KEYSTORE_NOT_FOUND_EXCEPTION_MESSAGE = certificatePath -> String.format("Failed to load the keystore from the classpath for the given path: [%s]", certificatePath);
    private static final String EMPTY_TRUST_MANAGER_FOR_TRUSTSTORE_EXCEPTION = "Could not create TrustStore because the provided TrustManager does not contain any trusted certificates";
    private static final String EMPTY_CERTIFICATES_EXCEPTION = "Could not create TrustStore because certificate is absent";

    private KeyStoreUtils() {}

    public static KeyStore loadKeyStore(String keystorePath, char[] keystorePassword) {
        return loadKeyStore(keystorePath, keystorePassword, KeyStore.getDefaultType());
    }

    public static KeyStore loadKeyStore(String keystorePath, char[] keystorePassword, String keystoreType) {
        try (InputStream keystoreInputStream = KeyStoreUtils.class.getClassLoader().getResourceAsStream(keystorePath)) {
            return loadKeyStore(
                    requireNotNull(keystoreInputStream, KEYSTORE_NOT_FOUND_EXCEPTION_MESSAGE.apply(keystorePath)),
                    keystorePassword,
                    keystoreType
            );
        } catch (Exception e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static KeyStore loadKeyStore(Path keystorePath, char[] keystorePassword) {
        return loadKeyStore(keystorePath, keystorePassword, KeyStore.getDefaultType());
    }

    public static KeyStore loadKeyStore(Path keystorePath, char[] keystorePassword, String keystoreType) {
        try (InputStream keystoreInputStream = Files.newInputStream(keystorePath, StandardOpenOption.READ)) {
            return loadKeyStore(keystoreInputStream, keystorePassword, keystoreType);
        } catch (Exception e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static KeyStore loadKeyStore(InputStream keystoreInputStream, char[] keystorePassword) {
        return loadKeyStore(
                requireNotNull(keystoreInputStream, EMPTY_INPUT_STREAM_EXCEPTION_MESSAGE),
                keystorePassword,
                KeyStore.getDefaultType()
        );
    }

    public static KeyStore loadKeyStore(InputStream keystoreInputStream, char[] keystorePassword, String keystoreType) {
        try {
            KeyStore keystore = KeyStore.getInstance(keystoreType);
            keystore.load(requireNotNull(keystoreInputStream, EMPTY_INPUT_STREAM_EXCEPTION_MESSAGE), keystorePassword);
            return keystore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static KeyStore createIdentityStore(Key privateKey, char[] privateKeyPassword, String alias, List<? extends Certificate> certificateChain) {
        return createIdentityStore(privateKey, privateKeyPassword, alias, certificateChain.toArray(new Certificate[]{}));
    }

    public static KeyStore createIdentityStore(Key privateKey, char[] privateKeyPassword, List<? extends Certificate> certificateChain) {
        return createIdentityStore(privateKey, privateKeyPassword, null, certificateChain.toArray(new Certificate[]{}));
    }

    @SafeVarargs
    public static <T extends Certificate> KeyStore createIdentityStore(Key privateKey, char[] privateKeyPassword, T... certificateChain) {
        return createIdentityStore(privateKey, privateKeyPassword, null, certificateChain);
    }

    @SafeVarargs
    public static <T extends Certificate> KeyStore createIdentityStore(Key privateKey, char[] privateKeyPassword, String alias, T... certificateChain) {
        try {
            KeyStore keyStore = createKeyStore();
            String privateKeyAlias = StringUtils.isBlank(alias) ? CertificateUtils.generateAlias(certificateChain[0]) : alias;
            keyStore.setKeyEntry(privateKeyAlias, privateKey, privateKeyPassword, certificateChain);
            return keyStore;
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static KeyStore createKeyStore() {
        return createKeyStore(DUMMY_PASSWORD.toCharArray());
    }

    public static KeyStore createKeyStore(char[] keyStorePassword) {
        return createKeyStore(KEYSTORE_TYPE, keyStorePassword);
    }

    public static KeyStore createKeyStore(String keyStoreType, char[] keyStorePassword) {
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null, keyStorePassword);
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    @SafeVarargs
    public static <T extends X509TrustManager> KeyStore createTrustStore(T... trustManagers) {
        List<X509Certificate> certificates = new ArrayList<>();
        for (T trustManager : trustManagers) {
            certificates.addAll(Arrays.asList(trustManager.getAcceptedIssuers()));
        }

        return createTrustStore(
                requireNotEmpty(certificates, EMPTY_TRUST_MANAGER_FOR_TRUSTSTORE_EXCEPTION)
        );
    }

    @SafeVarargs
    public static <T extends Certificate> KeyStore createTrustStore(T... certificates) {
        return createTrustStore(Arrays.asList(certificates));
    }

    public static <T extends Certificate> KeyStore createTrustStore(List<T> certificates) {
        try {
            KeyStore trustStore = createKeyStore();
            for (T certificate : requireNotEmpty(certificates, EMPTY_CERTIFICATES_EXCEPTION)) {
                String alias = CertificateUtils.generateAlias(certificate);
                boolean shouldAddCertificate = true;

                if (trustStore.containsAlias(alias)) {
                    for (int number = 0; number <= 1000; number++) {
                        String mayBeUniqueAlias = alias + "-" + number;
                        if (!trustStore.containsAlias(mayBeUniqueAlias)) {
                            alias = mayBeUniqueAlias;
                            shouldAddCertificate = true;
                            break;
                        } else {
                            shouldAddCertificate = false;
                        }
                    }
                }

                if (shouldAddCertificate) {
                    trustStore.setCertificateEntry(alias, certificate);
                }
            }
            return trustStore;
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static List<KeyStore> loadSystemKeyStores() {
        List<KeyStore> keyStores = new ArrayList<>();

        OperatingSystem operatingSystem = OperatingSystem.get();
        switch (operatingSystem) {
            case MAC: {
                KeyStore keychainStore = createKeyStore("KeychainStore", null);
                keyStores.add(keychainStore);

                List<Certificate> systemTrustedCertificates = MacCertificateUtils.getCertificates();
                KeyStore systemTrustStore = createTrustStore(systemTrustedCertificates);
                keyStores.add(systemTrustStore);
                break;
            }
            case LINUX: {
                List<Certificate> certificates = LinuxCertificateUtils.getCertificates();
                KeyStore linuxTrustStore = createTrustStore(certificates);
                keyStores.add(linuxTrustStore);
                break;
            }
            case ANDROID: {
                KeyStore androidCAStore = createKeyStore("AndroidCAStore", null);
                keyStores.add(androidCAStore);
                break;
            }
            case WINDOWS: {
                KeyStore windowsRootKeyStore = createKeyStore("Windows-ROOT", null);
                KeyStore windowsMyKeyStore = createKeyStore("Windows-MY", null);

                keyStores.add(windowsRootKeyStore);
                keyStores.add(windowsMyKeyStore);

                // Only available on Java 11 and 17+
                Stream.of("Windows-MY-CURRENTUSER", "Windows-MY-LOCALMACHINE", "Windows-ROOT-LOCALMACHINE", "Windows-ROOT-CURRENTUSER")
                        .map(keystoreType -> createKeyStoreIfAvailable(keystoreType, null))
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .forEach(keyStores::add);
                break;
            }
            default: {
                String resolvedOsName = OperatingSystem.UNKNOWN.getResolvedOsName();
                LOGGER.warn("No system KeyStores available for [{}]", resolvedOsName);
                return Collections.emptyList();
            }
        }

        return Collections.unmodifiableList(keyStores);
    }

    @SuppressWarnings("SameParameterValue")
    static Optional<KeyStore> createKeyStoreIfAvailable(String keyStoreType, char[] keyStorePassword) {
        try {
            KeyStore keyStore = createKeyStore(keyStoreType, keyStorePassword);
            LOGGER.debug("Successfully loaded KeyStore of the type [{}] having [{}] entries", keyStoreType, keyStore.size());
            return Optional.of(keyStore);
        } catch (Exception ignored) {
            LOGGER.debug("Failed to load KeyStore of the type [{}]", keyStoreType);
            return Optional.empty();
        }
    }

    public static List<Certificate> getCertificates(KeyStore keyStore) {
        return getAliasToCertificate(keyStore).values().stream()
                .collect(CollectorsUtils.toUnmodifiableList());
    }

    public static Map<String, Certificate> getAliasToCertificate(KeyStore keyStore) {
        try {
            Map<String, Certificate> aliasToCertificate = new HashMap<>();

            List<String> aliases = getAliases(keyStore);
            for (String alias : aliases) {
                if (keyStore.isCertificateEntry(alias)) {
                    Certificate certificate = keyStore.getCertificate(alias);
                    aliasToCertificate.put(alias, certificate);
                }
            }

            return Collections.unmodifiableMap(aliasToCertificate);
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static List<String> getAliases(KeyStore keyStore) {
        try {
            List<String> destinationAliases = new ArrayList<>();
            Enumeration<String> sourceAliases = keyStore.aliases();
            while (sourceAliases.hasMoreElements()) {
                String alias = sourceAliases.nextElement();
                destinationAliases.add(alias);
            }

            return Collections.unmodifiableList(destinationAliases);
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static void write(Path destination, KeyStore keyStore, char[] password) {
        IOUtils.write(destination, outputStream -> keyStore.store(outputStream, password));
    }

    public static int countAmountOfTrustMaterial(KeyStore keyStore) {
        return amountOfSpecifiedMaterial(keyStore, KeyStore::isCertificateEntry, Integer.MAX_VALUE);
    }

    public static int countAmountOfIdentityMaterial(KeyStore keyStore) {
        return amountOfSpecifiedMaterial(keyStore, KeyStore::isKeyEntry, Integer.MAX_VALUE);
    }

    public static boolean containsTrustMaterial(KeyStore keyStore) {
        return amountOfSpecifiedMaterial(keyStore, KeyStore::isCertificateEntry, 1) > 0;
    }

    public static boolean containsIdentityMaterial(KeyStore keyStore) {
        return amountOfSpecifiedMaterial(keyStore, KeyStore::isKeyEntry, 1) > 0;
    }

    private static int amountOfSpecifiedMaterial(KeyStore keyStore,
                                                 KeyStoreBiPredicate<KeyStore, String> predicate,
                                                 int upperBoundaryForMaterialCounter) {

        try {
            int materialCounter = 0;

            List<String> aliases = getAliases(keyStore);
            for (String alias : aliases) {
                if (materialCounter < upperBoundaryForMaterialCounter && predicate.test(keyStore, alias)) {
                    materialCounter++;
                }
            }
            return materialCounter;
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    private interface KeyStoreBiPredicate<T extends KeyStore, U> {
        boolean test(T t, U u) throws KeyStoreException;
    }

}
