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
package nl.altindag.ssl.hostnameverifier;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class BasicHostnameVerifierShould {

    @Test
    void verifyReturnsTrueWhenHostnameMatches() {
        SSLSession sslSession = mock(SSLSession.class);
        when(sslSession.getPeerHost()).thenReturn("some-host");

        HostnameVerifier hostnameVerifier = BasicHostNameVerifier.getInstance();

        boolean verify = hostnameVerifier.verify("some-host", sslSession);
        assertThat(verify).isTrue();
    }

    @Test
    void verifyReturnsTrueWhenHostnameMatchesWhileIgnoringCasing() {
        SSLSession sslSession = mock(SSLSession.class);
        when(sslSession.getPeerHost()).thenReturn("some-host");

        HostnameVerifier hostnameVerifier = BasicHostNameVerifier.getInstance();

        boolean verify = hostnameVerifier.verify("sOmE-hOsT", sslSession);
        assertThat(verify).isTrue();
    }

    @Test
    void verifyReturnsFalseWhenHostnameDoesNotMatch() {
        SSLSession sslSession = mock(SSLSession.class);
        when(sslSession.getPeerHost()).thenReturn("some-host");

        HostnameVerifier hostnameVerifier = BasicHostNameVerifier.getInstance();

        boolean verify = hostnameVerifier.verify("another-host", sslSession);
        assertThat(verify).isFalse();
    }

}