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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.X509ExtendedTrustManager;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.TrustManagerUtils TrustManagerUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 *
 * @author Hakan Altindag
 */
public class InflatableX509ExtendedTrustManager extends HotSwappableX509ExtendedTrustManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(InflatableX509ExtendedTrustManager.class);

    private final Path trustStorePath;
    private final char[] trustStorePassword;
    private final KeyStore trustStore;

    public InflatableX509ExtendedTrustManager(Path trustStorePath, char[] trustStorePassword, String trustStoreType) {
        super(TrustManagerUtils.createDummyTrustManager());
        this.trustStorePath = trustStorePath;
        this.trustStorePassword = trustStorePassword;

        myWriteLock.lock();

        try {
            if (Files.exists(trustStorePath)) {
                trustStore = KeyStoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
            } else {
                trustStore = KeyStoreUtils.createKeyStore(trustStoreType, trustStorePassword);
                KeyStoreUtils.write(trustStorePath, trustStore, trustStorePassword);
            }
        } finally {
            myWriteLock.unlock();
        }
    }

    private void addCertificates(Path... certificatePaths) {
        List<Certificate> certificates = CertificateUtils.loadCertificate(certificatePaths);
        addCertificates(certificates);
    }

    public void addCertificates(Certificate... certificates) {
        addCertificates(Arrays.asList(certificates));
    }

    public void addCertificates(List<? extends Certificate> certificates) {
        myWriteLock.lock();

        try {
            List<String> aliases = new ArrayList<>();
            for (Certificate certificate : certificates) {
                String alias = CertificateUtils.generateAlias(certificate);
                aliases.add(alias);
                trustStore.setCertificateEntry(alias, certificate);
            }
            KeyStoreUtils.write(trustStorePath, trustStore, trustStorePassword);
            aliases.forEach(alias -> LOGGER.info("Added certificate for {} to {}", alias, trustStorePath));
            X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
            setTrustManager(trustManager);
        } catch (Exception e) {
            LOGGER.error("Cannot add certificate", e);
        } finally {
            myWriteLock.unlock();
        }
    }

}
