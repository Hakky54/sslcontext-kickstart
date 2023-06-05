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

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiPredicate;
import java.util.stream.IntStream;
import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.TestConstants;
import nl.altindag.ssl.util.KeyStoreUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class InflatableX509ExtendedTrustManagerShould {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final char[] TRUSTSTORE_PASSWORD = new char[]{'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystore/";

    @Test
    void initiallyBeEmpty() {
        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(null, null, null, null);

        X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();
        assertThat(acceptedIssuers).isEmpty();
    }

    @Test
    void initiallyContainDummyTrustManager() {
        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(null, null, null, null);

        X509ExtendedTrustManager innerTrustManager = trustManager.getInnerTrustManager();
        assertThat(innerTrustManager).isInstanceOf(DummyX509ExtendedTrustManager.class);
    }

    @Test
    void addNewlyTrustedCertificates() throws KeyStoreException {
        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustedCerts).hasSizeGreaterThan(0);

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(null, null, null, null);
        trustManager.addCertificates(Arrays.asList(trustedCerts));

        assertThat(trustManager.getAcceptedIssuers()).containsExactly(trustedCerts);
        assertThat(logCaptor.getInfoLogs()).containsExactly("Added certificate for [cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us]");
    }

    @Test
    void addNewlyTrustedCertificatesWhileAlsoWritingToAKeyStoreOnTheFileSystem() throws KeyStoreException, IOException {
        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustedCerts).hasSizeGreaterThan(0);

        Path trustStoreDestination = Paths.get(TestConstants.HOME_DIRECTORY, "inflatable-truststore.p12");
        assertThat(Files.exists(trustStoreDestination)).isFalse();

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, "secret".toCharArray(), "PKCS12", (chain, authType) -> true);
        trustManager.addCertificates(Arrays.asList(trustedCerts));

        assertThat(trustManager.getAcceptedIssuers()).containsExactly(trustedCerts);
        assertThat(logCaptor.getInfoLogs()).containsExactly("Added certificate for [cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us]");

        assertThat(Files.exists(trustStoreDestination)).isTrue();
        KeyStore inflatedTrustStore = KeyStoreUtils.loadKeyStore(trustStoreDestination, "secret".toCharArray(), "PKCS12");
        assertThat(KeyStoreTestUtils.getTrustedX509Certificates(inflatedTrustStore)).containsExactly(trustedCerts);

        Files.delete(trustStoreDestination);
    }

    @Test
    void callPredicateAndAddCertificatesIfTrusted() throws KeyStoreException, IOException, CertificateException {
        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate notYetTrustedCert = KeyStoreTestUtils.getTrustedX509Certificates(trustStore)[0];

        Path trustStoreDestination = Paths.get(TestConstants.HOME_DIRECTORY, "inflatable-truststore.p12");
        assertThat(Files.exists(trustStoreDestination)).isFalse();

        AtomicBoolean shouldTrust = new AtomicBoolean(false);
        BiPredicate<X509Certificate[], String> predicate = (chain, authType) -> shouldTrust.get();
        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, "secret".toCharArray(), "PKCS12", predicate);

        Assertions.assertThrows(CertificateException.class, () -> trustManager.checkServerTrusted(new X509Certificate[] {notYetTrustedCert}, "RSA"));
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();

        shouldTrust.set(true);
        trustManager.checkServerTrusted(new X509Certificate[] {notYetTrustedCert}, null);

        assertThat(trustManager.getAcceptedIssuers()).containsExactly(notYetTrustedCert);
        assertThat(logCaptor.getInfoLogs()).containsExactly("Added certificate for [cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us]");

        assertThat(Files.exists(trustStoreDestination)).isTrue();
        KeyStore inflatedTrustStore = KeyStoreUtils.loadKeyStore(trustStoreDestination, "secret".toCharArray(), "PKCS12");
        assertThat(KeyStoreTestUtils.getTrustedX509Certificates(inflatedTrustStore)).containsExactly(notYetTrustedCert);

        Files.delete(trustStoreDestination);
    }

    @Test
    void onlyCallPredicateOnceWhenConcurrentThreadsCheckForTheSameCertificate() throws KeyStoreException, IOException, InterruptedException, ExecutionException {
        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate notYetTrustedCert = KeyStoreTestUtils.getTrustedX509Certificates(trustStore)[0];

        Path trustStoreDestination = Paths.get(TestConstants.HOME_DIRECTORY, "inflatable-truststore.p12");
        assertThat(Files.exists(trustStoreDestination)).isFalse();

        AtomicBoolean shouldTrust = new AtomicBoolean(true);
        BiPredicate<X509Certificate[], String> predicate = (chain, authType) -> {
            // Only the first call to the predicate will return true
            if (shouldTrust.getAndSet(false)) {
                return true;
            }
            // Following calls (if any, but we only expect one) will throw
            throw new IllegalStateException("Predicate should only be called once");
        };
        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, "secret".toCharArray(), "PKCS12", predicate);

        int threadCount = Runtime.getRuntime().availableProcessors();
        ExecutorService exec = Executors.newFixedThreadPool(threadCount);
        var futureList = new ArrayList<Future<?>>();
        IntStream.of(threadCount).forEach( i -> {
            futureList.add(exec.submit(() -> {
                try {
                    trustManager.checkServerTrusted(new X509Certificate[] {notYetTrustedCert}, "RSA");
                } catch (CertificateException e) {
                    throw new RuntimeException(e);
                }
            }));
        });
        for (Future<?> future : futureList) {
            future.get();
        }

        assertThat(trustManager.getAcceptedIssuers()).containsExactly(notYetTrustedCert);
        assertThat(logCaptor.getInfoLogs()).containsExactly("Added certificate for [cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us]");

        assertThat(Files.exists(trustStoreDestination)).isTrue();
        KeyStore inflatedTrustStore = KeyStoreUtils.loadKeyStore(trustStoreDestination, "secret".toCharArray(), "PKCS12");
        assertThat(KeyStoreTestUtils.getTrustedX509Certificates(inflatedTrustStore)).containsExactly(notYetTrustedCert);

        Files.delete(trustStoreDestination);
    }

}
