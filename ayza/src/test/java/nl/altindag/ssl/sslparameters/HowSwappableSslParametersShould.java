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
package nl.altindag.ssl.sslparameters;

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLParameters;

import java.security.AlgorithmConstraints;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * @author Hakan Altindag
 */
class HowSwappableSslParametersShould {

    @Test
    void setSslParameters() {
        SSLParameters innerSslParameters = mock(SSLParameters.class);
        SSLParameters newInnerSslParameters = mock(SSLParameters.class);

        HotSwappableSSLParameters swappableSSLParameters = new HotSwappableSSLParameters(innerSslParameters);
        assertThat(swappableSSLParameters.getInnerSslParameters()).isEqualTo(innerSslParameters);

        swappableSSLParameters.setSslParameters(newInnerSslParameters);
        assertThat(swappableSSLParameters.getInnerSslParameters())
                .isNotEqualTo(innerSslParameters)
                .isEqualTo(newInnerSslParameters);
    }

    @Test
    void getInnerSslParameters() {
        SSLParameters innerSslParameters = mock(SSLParameters.class);
        HotSwappableSSLParameters swappableSSLParameters = new HotSwappableSSLParameters(innerSslParameters);

        assertThat(swappableSSLParameters.getInnerSslParameters()).isEqualTo(innerSslParameters);
    }

    @Test
    void getCipherSuites() {
        SSLParameters innerSslParameters = mock(SSLParameters.class);
        HotSwappableSSLParameters swappableSSLParameters = new HotSwappableSSLParameters(innerSslParameters);

        swappableSSLParameters.getCipherSuites();
        verify(innerSslParameters, times(1)).getCipherSuites();
    }

    @Test
    void getProtocols() {
        SSLParameters innerSslParameters = mock(SSLParameters.class);
        HotSwappableSSLParameters swappableSSLParameters = new HotSwappableSSLParameters(innerSslParameters);

        swappableSSLParameters.getProtocols();
        verify(innerSslParameters, times(1)).getProtocols();
    }

    @Test
    void getWantClientAuth() {
        SSLParameters innerSslParameters = mock(SSLParameters.class);
        HotSwappableSSLParameters swappableSSLParameters = new HotSwappableSSLParameters(innerSslParameters);

        swappableSSLParameters.getWantClientAuth();
        verify(innerSslParameters, times(1)).getWantClientAuth();
    }

    @Test
    void getNeedClientAuth() {
        SSLParameters innerSslParameters = mock(SSLParameters.class);
        HotSwappableSSLParameters swappableSSLParameters = new HotSwappableSSLParameters(innerSslParameters);

        swappableSSLParameters.getNeedClientAuth();
        verify(innerSslParameters, times(1)).getNeedClientAuth();
    }

    @Test
    void getAlgorithmConstraints() {
        SSLParameters innerSslParameters = mock(SSLParameters.class);
        HotSwappableSSLParameters swappableSSLParameters = new HotSwappableSSLParameters(innerSslParameters);

        swappableSSLParameters.getAlgorithmConstraints();
        verify(innerSslParameters, times(1)).getAlgorithmConstraints();
    }

    @Test
    void getEndpointIdentificationAlgorithm() {
        SSLParameters innerSslParameters = mock(SSLParameters.class);
        HotSwappableSSLParameters swappableSSLParameters = new HotSwappableSSLParameters(innerSslParameters);

        swappableSSLParameters.getEndpointIdentificationAlgorithm();
        verify(innerSslParameters, times(1)).getEndpointIdentificationAlgorithm();
    }

    @Test
    void setCipherSuites() {
        SSLParameters innerSslParameters = mock(SSLParameters.class);
        HotSwappableSSLParameters swappableSSLParameters = new HotSwappableSSLParameters(innerSslParameters);

        swappableSSLParameters.setCipherSuites(new String[]{"some-cipher"});
        verify(innerSslParameters, times(1)).setCipherSuites(any());
    }

    @Test
    void setProtocols() {
        SSLParameters innerSslParameters = mock(SSLParameters.class);
        HotSwappableSSLParameters swappableSSLParameters = new HotSwappableSSLParameters(innerSslParameters);

        swappableSSLParameters.setProtocols(new String[]{"some-protocol"});
        verify(innerSslParameters, times(1)).setProtocols(any());
    }

    @Test
    void setWantClientAuth() {
        SSLParameters innerSslParameters = mock(SSLParameters.class);
        HotSwappableSSLParameters swappableSSLParameters = new HotSwappableSSLParameters(innerSslParameters);

        swappableSSLParameters.setWantClientAuth(true);
        verify(innerSslParameters, times(1)).setWantClientAuth(true);
    }

    @Test
    void setNeedClientAuth() {
        SSLParameters innerSslParameters = mock(SSLParameters.class);
        HotSwappableSSLParameters swappableSSLParameters = new HotSwappableSSLParameters(innerSslParameters);

        swappableSSLParameters.setNeedClientAuth(true);
        verify(innerSslParameters, times(1)).setNeedClientAuth(true);
    }

    @Test
    void setAlgorithmConstraints() {
        SSLParameters innerSslParameters = mock(SSLParameters.class);
        HotSwappableSSLParameters swappableSSLParameters = new HotSwappableSSLParameters(innerSslParameters);

        swappableSSLParameters.setAlgorithmConstraints(mock(AlgorithmConstraints.class));
        verify(innerSslParameters, times(1)).setAlgorithmConstraints(any());
    }

    @Test
    void setEndpointIdentificationAlgorithm() {
        SSLParameters innerSslParameters = mock(SSLParameters.class);
        HotSwappableSSLParameters swappableSSLParameters = new HotSwappableSSLParameters(innerSslParameters);

        swappableSSLParameters.setEndpointIdentificationAlgorithm("some-algorithm");
        verify(innerSslParameters, times(1)).setEndpointIdentificationAlgorithm(anyString());
    }

}
