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

import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.util.KeyStoreUtils;
import org.junit.jupiter.api.Test;

import javax.net.ssl.X509ExtendedTrustManager;
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
        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();

        X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();
        assertThat(acceptedIssuers).isEmpty();
    }

    @Test
    void initiallyContainDummyTrustManager() {
        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();

        X509ExtendedTrustManager innerTrustManager = trustManager.getInnerTrustManager();
        assertThat(innerTrustManager).isInstanceOf(DummyX509ExtendedTrustManager.class);
    }

    @Test
    void addNewlyTrustedCertificates() throws KeyStoreException {
        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustedCerts).hasSizeGreaterThan(0);

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();
        trustManager.addCertificates(Arrays.asList(trustedCerts));

        assertThat(trustManager.getAcceptedIssuers()).containsExactly(trustedCerts);
        assertThat(logCaptor.getInfoLogs()).containsExactly("Added certificate for [cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us]");
    }

}
