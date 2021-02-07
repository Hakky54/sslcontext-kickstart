/*
 * Copyright 2019-2021 the original author or authors.
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

package nl.altindag.ssl;

import io.netty.handler.ssl.SslContext;
import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.util.KeyStoreUtils;
import nl.altindag.ssl.util.NettySslUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.util.function.Tuple2;

import java.io.IOException;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class SSLFactoryIT {

    private static final Logger LOGGER = LoggerFactory.getLogger(SSLFactoryIT.class);

    @BeforeAll
    static void disableNettyVerboseLogging() {
        LogCaptor.forName("io.netty").disableLogs();
        LogCaptor.forName("reactor.netty").disableLogs();
    }

    @Test
    void executeHttpsRequestWithMutualAuthentication() throws IOException {
        LogCaptor logCaptor = LogCaptor.forName("nl.altindag.ssl");

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/badssl-identity.p12", "badssl.com".toCharArray())
                .withTrustMaterial("keystores-for-unit-tests/badssl-truststore.p12", "badssl.com".toCharArray())
                .withTrustMaterial(KeyStoreUtils.createKeyStore()) // Adding additional trust material forces usage of CompositeX509ExtendedTrustManager and verbose logging
                .build();

        SslContext sslContext = NettySslUtils.forClient(sslFactory).build();
        HttpClient httpClient = HttpClient.create().secure(sslSpec -> sslSpec.sslContext(sslContext));

        Integer statusCode = httpClient.get()
                .uri("https://client.badssl.com/")
                .responseSingle((response, body) -> Mono.zip(body.asString(), Mono.just(response.status().code())))
                .map(Tuple2::getT2)
                .block();

        if (Objects.requireNonNull(statusCode) == 400) {
            LOGGER.warn("Certificate may have expired and needs to be updated");
        } else {
            assertThat(statusCode).isEqualTo(200);
            assertThat(logCaptor.getLogs()).contains("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
        }
    }

    @Test
    @Disabled("The server [https://prod.idrix.eu/secure/] has a rate limiter which will only allow couple of requests from a single machine. " +
              "Therefore this test is disabled to prevent a failing build.")
    void executeHttpsRequestWithMutualAuthenticationForMultipleClientIdentitiesWithSingleSslConfiguration() throws IOException {
        LogCaptor logCaptor = LogCaptor.forName("nl.altindag.ssl");

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("keystores-for-unit-tests/badssl-identity.p12", "badssl.com".toCharArray())
                .withIdentityMaterial("keystores-for-unit-tests/prod.idrix.eu-identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystores-for-unit-tests/badssl-truststore.p12", "badssl.com".toCharArray())
                .withTrustMaterial("keystores-for-unit-tests/prod.idrix.eu-truststore.jks", "secret".toCharArray())
                .build();

        SslContext sslContext = NettySslUtils.forClient(sslFactory).build();
        HttpClient httpClient = HttpClient.create().secure(sslSpec -> sslSpec.sslContext(sslContext));

        Tuple2<String, Integer> responseEntity = httpClient.get()
                .uri("https://client.badssl.com/")
                .responseSingle((response, body) -> Mono.zip(body.asString(), Mono.just(response.status().code())))
                .block();

        if (Objects.requireNonNull(responseEntity).getT2() == 400) {
            LOGGER.warn("Certificate may have expired and needs to be updated");
        } else {
            assertThat(responseEntity.getT2()).isEqualTo(200);
            assertThat(logCaptor.getLogs()).contains("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
        }

        responseEntity = httpClient.get()
                .uri("https://prod.idrix.eu/secure/")
                .responseSingle((response, body) -> Mono.zip(body.asString(), Mono.just(response.status().code())))
                .block();

        if (Objects.requireNonNull(responseEntity).getT2() == 400) {
            LOGGER.warn("Certificate may have expired and needs to be updated");
        } else {
            assertThat(responseEntity.getT2()).isEqualTo(200);
            assertThat(responseEntity.getT1()).contains("SSL Authentication OK");
            assertThat(responseEntity.getT1()).doesNotContain("No SSL client certificate presented");
            assertThat(logCaptor.getLogs()).contains("Received the following server certificate: [CN=prod.idrix.eu]");
        }

    }
}
