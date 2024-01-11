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

import nl.altindag.ssl.SSLFactory;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLParameters;

import static org.mockito.Mockito.spy;

/**
 * @author Hakan Altindag
 */
class SSLParametersUtilsShould {

    @Test
    void useBaseSslParametersIfItIsFilledWithData() {
        SSLParameters baseSslParameters = spy(
                new SSLParameters(
                        new String[]{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
                        new String[]{"TLSv1.2"}
                )
        );

        SSLFactory sslFactory = SSLFactory.builder()
                .withDummyTrustMaterial()
                .build();

        SSLParameters mergedParameters = SSLParametersUtils.merge(baseSslParameters, sslFactory.getSslParameters());

        Assertions.assertThat(mergedParameters.getCipherSuites()).containsExactly("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        Assertions.assertThat(mergedParameters.getProtocols()).containsExactly("TLSv1.2");
    }

}
