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

import nl.altindag.ssl.model.TrustManagerParameters;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
@SuppressWarnings("ConstantValue")
@ExtendWith(MockitoExtension.class)
class EnhanceableX509ExtendedTrustManagerShould {

    @Test
    void callChainAndAuthTypeValidatorWhenPresentAndNotTheBaseTrustManagerWhenCallingCheckClientTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = trustManagerParameters -> true;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);

        trustManager.checkClientTrusted(certificateChain, authType);

        verify(baseTrustManager, times(0)).checkClientTrusted(certificateChain, authType);
    }

    @Test
    void notCallChainAndAuthTypeValidatorWhenAbsentAndShouldCallTheBaseTrustManagerWhenCallingCheckClientTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = null;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);

        trustManager.checkClientTrusted(certificateChain, authType);

        verify(baseTrustManager, times(1)).checkClientTrusted(certificateChain, authType);
    }

    @Test
    void callBaseTrustManagerWhenChainAndAuthTypeValidatorEvaluatesToFalseWhenCallingCheckClientTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = trustManagerParameters -> false;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);

        trustManager.checkClientTrusted(certificateChain, authType);

        verify(baseTrustManager, times(1)).checkClientTrusted(certificateChain, authType);
    }

    @Test
    void callChainAndAuthTypeWithSocketValidatorWhenPresentAndNotTheBaseTrustManagerWhenCallingCheckClientTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = trustManagerParameters -> true;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        Socket socket = mock(Socket.class);

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);

        trustManager.checkClientTrusted(certificateChain, authType, socket);

        verify(baseTrustManager, times(0)).checkClientTrusted(certificateChain, authType, socket);
    }

    @Test
    void notCallChainAndAuthTypeWithSocketValidatorWhenAbsentAndShouldCallTheBaseTrustManagerWhenCallingCheckClientTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = null;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        Socket socket = mock(Socket.class);

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);

        trustManager.checkClientTrusted(certificateChain, authType, socket);

        verify(baseTrustManager, times(1)).checkClientTrusted(certificateChain, authType, socket);
    }

    @Test
    void callBaseTrustManagerWhenChainAndAuthTypeWithSocketValidatorEvaluatesToFalseWhenCallingCheckClientTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = trustManagerParameters -> false;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        Socket socket = mock(Socket.class);

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);

        trustManager.checkClientTrusted(certificateChain, authType, socket);

        verify(baseTrustManager, times(1)).checkClientTrusted(certificateChain, authType, socket);
    }

    @Test
    void callChainAndAuthTypeWithSSLEngineValidatorWhenPresentAndNotTheBaseTrustManagerWhenCallingCheckClientTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = trustManagerParameters -> true;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        SSLEngine sslEngine = mock(SSLEngine.class);

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);

        trustManager.checkClientTrusted(certificateChain, authType, sslEngine);

        verify(baseTrustManager, times(0)).checkClientTrusted(certificateChain, authType, sslEngine);
    }

    @Test
    void notCallChainAndAuthTypeWithSSLEngineValidatorWhenAbsentAndShouldCallTheBaseTrustManagerWhenCallingCheckClientTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = null;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        SSLEngine sslEngine = mock(SSLEngine.class);

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);

        trustManager.checkClientTrusted(certificateChain, authType, sslEngine);

        verify(baseTrustManager, times(1)).checkClientTrusted(certificateChain, authType, sslEngine);
    }

    @Test
    void callBaseTrustManagerWhenChainAndAuthTypeWithSSLEngineValidatorEvaluatesToFalseWhenCallingCheckClientTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = trustManagerParameters -> false;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        SSLEngine sslEngine = mock(SSLEngine.class);

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);

        trustManager.checkClientTrusted(certificateChain, authType, sslEngine);

        verify(baseTrustManager, times(1)).checkClientTrusted(certificateChain, authType, sslEngine);
    }

    @Test
    void callChainAndAuthTypeValidatorWhenPresentAndNotTheBaseTrustManagerWhenCallingCheckServerTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = trustManagerParameters -> true;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);
        trustManager.checkServerTrusted(certificateChain, authType);

        verify(baseTrustManager, times(0)).checkServerTrusted(certificateChain, authType);
    }

    @Test
    void notCallChainAndAuthTypeValidatorWhenAbsentAndShouldCallTheBaseTrustManagerWhenCallingCheckServerTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = null;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);
        trustManager.checkServerTrusted(certificateChain, authType);

        verify(baseTrustManager, times(1)).checkServerTrusted(certificateChain, authType);
    }

    @Test
    void callBaseTrustManagerWhenChainAndAuthTypeValidatorEvaluatesToFalseWhenCallingCheckServerTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = trustManagerParameters -> false;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);
        trustManager.checkServerTrusted(certificateChain, authType);

        verify(baseTrustManager, times(1)).checkServerTrusted(certificateChain, authType);
    }

    @Test
    void callChainAndAuthTypeWithSocketValidatorWhenPresentAndNotTheBaseTrustManagerWhenCallingCheckServerTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = trustManagerParameters -> true;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        Socket socket = mock(Socket.class);

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);
        trustManager.checkServerTrusted(certificateChain, authType, socket);

        verify(baseTrustManager, times(0)).checkServerTrusted(certificateChain, authType, socket);
    }

    @Test
    void notCallChainAndAuthTypeWithSocketValidatorWhenAbsentAndShouldCallTheBaseTrustManagerWhenCallingCheckServerTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = null;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        Socket socket = mock(Socket.class);

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);
        trustManager.checkServerTrusted(certificateChain, authType, socket);

        verify(baseTrustManager, times(1)).checkServerTrusted(certificateChain, authType, socket);
    }

    @Test
    void callBaseTrustManagerWhenChainAndAuthTypeWithSocketValidatorEvaluatesToFalseWhenCallingCheckServerTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = trustManagerParameters -> false;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        Socket socket = mock(Socket.class);

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);
        trustManager.checkServerTrusted(certificateChain, authType, socket);

        verify(baseTrustManager, times(1)).checkServerTrusted(certificateChain, authType, socket);
    }

    @Test
    void callChainAndAuthTypeWithSSLEngineValidatorWhenPresentAndNotTheBaseTrustManagerWhenCallingCheckServerTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = trustManagerParameters -> true;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        SSLEngine sslEngine = mock(SSLEngine.class);

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);
        trustManager.checkServerTrusted(certificateChain, authType, sslEngine);

        verify(baseTrustManager, times(0)).checkServerTrusted(certificateChain, authType, sslEngine);
    }

    @Test
    void notCallChainAndAuthTypeWithSSLEngineValidatorWhenAbsentAndShouldCallTheBaseTrustManagerWhenCallingCheckServerTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = null;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        SSLEngine sslEngine = mock(SSLEngine.class);

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);
        trustManager.checkServerTrusted(certificateChain, authType, sslEngine);

        verify(baseTrustManager, times(1)).checkServerTrusted(certificateChain, authType, sslEngine);
    }

    @Test
    void callBaseTrustManagerWhenChainAndAuthTypeWithSSLEngineValidatorEvaluatesToFalseWhenCallingCheckServerTrusted() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        Predicate<TrustManagerParameters> trustManagerParametersPredicate = trustManagerParameters -> false;

        X509Certificate[] certificateChain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        SSLEngine sslEngine = mock(SSLEngine.class);

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, trustManagerParametersPredicate, false);
        trustManager.checkServerTrusted(certificateChain, authType, sslEngine);

        verify(baseTrustManager, times(1)).checkServerTrusted(certificateChain, authType, sslEngine);
    }

    @Test
    void shouldConcealTrustedCertificatesWhenEnabled() {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        when(baseTrustManager.getAcceptedIssuers()).thenReturn(new X509Certificate[]{mock(X509Certificate.class)});
        assertThat(baseTrustManager.getAcceptedIssuers()).hasSize(1);

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, null, true);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
    }

    @Test
    void shouldNotConcealTrustedCertificatesWhenDisabled() {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        when(baseTrustManager.getAcceptedIssuers()).thenReturn(new X509Certificate[]{mock(X509Certificate.class)});
        assertThat(baseTrustManager.getAcceptedIssuers()).hasSize(1);

        EnhanceableX509ExtendedTrustManager trustManager = new EnhanceableX509ExtendedTrustManager(baseTrustManager, null, false);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

}
