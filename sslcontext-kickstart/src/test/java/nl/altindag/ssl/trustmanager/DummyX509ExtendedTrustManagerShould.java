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

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Hakan Altindag
 */
class DummyX509ExtendedTrustManagerShould {

    private final X509ExtendedTrustManager victim = DummyX509ExtendedTrustManager.getInstance();

    @Test
    void checkClientTrusted() {
        assertThatThrownBy(() -> victim.checkClientTrusted(null, null))
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("No X509ExtendedTrustManager implementation available");
    }

    @Test
    void checkClientTrustedWithSslEngine() {
        assertThatThrownBy(() -> victim.checkClientTrusted(null, null, (SSLEngine) null))
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("No X509ExtendedTrustManager implementation available");
    }

    @Test
    void checkClientTrustedWithSocket() {
        assertThatThrownBy(() -> victim.checkClientTrusted(null, null, (Socket) null))
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("No X509ExtendedTrustManager implementation available");
    }

    @Test
    void checkServerTrusted() {
        assertThatThrownBy(() -> victim.checkServerTrusted(null, null))
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("No X509ExtendedTrustManager implementation available");
    }

    @Test
    void checkServerTrustedWithSslEngine() {
        assertThatThrownBy(() -> victim.checkServerTrusted(null, null, (SSLEngine) null))
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("No X509ExtendedTrustManager implementation available");
    }

    @Test
    void checkServerTrustedWitSocket() {
        assertThatThrownBy(() -> victim.checkServerTrusted(null, null, (Socket) null))
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("No X509ExtendedTrustManager implementation available");
    }

    @Test
    void getAcceptedIssuers() {
        assertThat(victim.getAcceptedIssuers()).isEmpty();
    }

}
