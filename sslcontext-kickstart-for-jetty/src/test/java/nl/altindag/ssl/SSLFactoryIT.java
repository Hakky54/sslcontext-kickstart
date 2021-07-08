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

import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.util.JettySslUtils;
import nl.altindag.ssl.util.KeyStoreUtils;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class SSLFactoryIT {

    @Test
    void executeHttpsRequestWithMutualAuthentication() throws Exception {
        LogCaptor logCaptor = LogCaptor.forName("nl.altindag.ssl");

        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("keystore/badssl-identity.p12", "badssl.com".toCharArray())
                .withTrustMaterial("keystore/badssl-truststore.p12", "badssl.com".toCharArray())
                .withTrustMaterial(KeyStoreUtils.createKeyStore()) // Adding additional trust material forces usage of CompositeX509ExtendedTrustManager and verbose logging
                .build();

        SslContextFactory.Client sslContextFactory = JettySslUtils.forClient(sslFactory);

        HttpClient httpClient = new HttpClient(sslContextFactory);
        httpClient.start();

        ContentResponse contentResponse = httpClient.newRequest("https://client.badssl.com/")
                .method(HttpMethod.GET)
                .send();

        httpClient.stop();
        logCaptor.close();

        int statusCode = contentResponse.getStatus();

        if (statusCode == 400) {
            Assertions.fail("Certificate may have expired and needs to be updated");
        } else {
            assertThat(statusCode).isEqualTo(200);
            assertThat(logCaptor.getLogs()).contains("Received the following server certificate: [CN=*.badssl.com, O=Lucas Garron Torres, L=Walnut Creek, ST=California, C=US]");
        }
    }

}
