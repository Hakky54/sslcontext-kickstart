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
package nl.altindag.ssl.trustmanager;

import nl.altindag.ssl.util.CertificateUtils;
import nl.altindag.ssl.util.KeyStoreUtils;
import nl.altindag.ssl.util.TrustManagerUtils;
import nl.altindag.ssl.util.internal.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.BiPredicate;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.TrustManagerUtils TrustManagerUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 * <p>
 * The Inflatable TrustManager has the capability to grow with newly trusted certificates at any moment in time.
 * It can be either added manually with {@link TrustManagerUtils#addCertificate(X509ExtendedTrustManager, List)} or by providing
 * a predicate in the constructor of this class so it can evaluate every certificate whether it should be trusted or not.
 * Next to that it will write the trusted certificates to the file system as a keystore file if the properties are provided in the
 * constructor. If this is not the case it will still use an in-memory keystore to maintain the newly added certificates, however
 * the state will get lost when the application has been restarted.
 *
 * @author Hakan Altindag
 */
public class InflatableX509ExtendedTrustManager extends HotSwappableX509ExtendedTrustManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(InflatableX509ExtendedTrustManager.class);

    private final KeyStore trustStore;
    private final Path trustStorePath;
    private final char[] trustStorePassword;
    private final String trustStoreType;
    private final BiPredicate<X509Certificate[], String> certificateAndAuthTypeTrustPredicate;

    public InflatableX509ExtendedTrustManager(Path trustStorePath,
                                              char[] trustStorePassword,
                                              String trustStoreType,
                                              BiPredicate<X509Certificate[], String> certificateAndAuthTypeTrustPredicate) {

        super(TrustManagerUtils.createDummyTrustManager());

        writeLock.lock();

        try {
            this.trustStorePath = trustStorePath;
            this.trustStorePassword = trustStorePassword;
            this.trustStoreType = trustStoreType;

            this.certificateAndAuthTypeTrustPredicate = Optional.ofNullable(certificateAndAuthTypeTrustPredicate)
                    .orElse((chain, authType) -> false);

            if (trustStorePath != null && trustStorePassword != null && StringUtils.isNotBlank(trustStoreType)) {
                if (Files.exists(trustStorePath)) {
                    trustStore = KeyStoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
                } else {
                    trustStore = KeyStoreUtils.createKeyStore(trustStoreType, trustStorePassword);
                }
            } else {
                trustStore = KeyStoreUtils.createKeyStore();
            }
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(trustManager -> super.checkServerTrusted(chain, authType), chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkTrusted(trustManager -> super.checkServerTrusted(chain, authType, socket), chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkTrusted(trustManager -> super.checkServerTrusted(chain, authType, sslEngine), chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(trustManager -> super.checkClientTrusted(chain, authType), chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkTrusted(trustManager -> super.checkClientTrusted(chain, authType, socket), chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkTrusted(trustManager -> super.checkClientTrusted(chain, authType, sslEngine), chain, authType);
    }

    private void checkTrusted(TrustManagerConsumer trustManagerConsumer, X509Certificate[] chain, String authType) throws CertificateException {
        try {
            // Use a read lock first in order to be more efficient
            readLock.lock();
            try {
                trustManagerConsumer.checkTrusted(this);
            } finally {
                readLock.unlock();
            }
        } catch (CertificateException e) {
            writeLock.lock();
            // Recheck in a write lock, in case of a concurrent update (kind of double-checked locking)
            try {
                trustManagerConsumer.checkTrusted(this);
            } catch (CertificateException e2) {
                boolean shouldBeTrusted = certificateAndAuthTypeTrustPredicate.test(chain, authType);
                if (shouldBeTrusted) {
                    addCertificates(Collections.singletonList(chain[0]));
                } else {
                    throw e2;
                }
            } finally {
                writeLock.unlock();
            }
        }
    }

    public void addCertificates(List<X509Certificate> certificates) {
        writeLock.lock();

        try {
            for (Certificate certificate : certificates) {
                String alias = CertificateUtils.generateAlias(certificate);
                trustStore.setCertificateEntry(alias, certificate);
                LOGGER.info("Added certificate for [{}]", alias);
            }
            X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
            setTrustManager(trustManager);

            if (trustStorePath != null && trustStoreType != null) {
                KeyStoreUtils.write(trustStorePath, trustStore, trustStorePassword);
            }
        } catch (KeyStoreException e) {
            LOGGER.error("Cannot add certificate", e);
        } finally {
            writeLock.unlock();
        }
    }

}
