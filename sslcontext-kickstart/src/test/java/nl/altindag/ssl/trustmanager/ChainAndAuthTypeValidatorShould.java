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

package nl.altindag.ssl.trustmanager;

import nl.altindag.ssl.util.KeyStoreUtils;
import nl.altindag.ssl.util.TrustManagerUtils;
import org.junit.jupiter.api.Test;

import javax.net.ssl.X509ExtendedTrustManager;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class ChainAndAuthTypeValidatorShould {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final char[] TRUSTSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystore/";

    @Test
    void test() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();

        ChainAndAuthTypeValidator validator = (certificateChain, authType) -> certificateChain[0].getSubjectX500Principal().getName().contains("Google");
        validator.test(acceptedIssuers, "RSA");

        assertThat(validator.test(acceptedIssuers, "RSA")).isTrue();
    }

    @Test
    void and() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();

        ChainAndAuthTypeValidator validator = ((ChainAndAuthTypeValidator) (certificateChain, authType) -> certificateChain[0].getSubjectX500Principal().getName().contains("Google"))
                .and((certificateChain, authType) -> certificateChain[0].getSubjectX500Principal().getName().contains("Mountain View"));
        validator.test(acceptedIssuers, "RSA");

        assertThat(validator.test(acceptedIssuers, "RSA")).isTrue();
    }

    @Test
    void or() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();

        ChainAndAuthTypeValidator validator = ((ChainAndAuthTypeValidator) (certificateChain, authType) -> certificateChain[0].getSubjectX500Principal().getName().contains("Google"))
                .or((certificateChain, authType) -> certificateChain[0].getSubjectX500Principal().getName().contains("Donald"));
        validator.test(acceptedIssuers, "RSA");

        assertThat(validator.test(acceptedIssuers, "RSA")).isTrue();
    }

}
