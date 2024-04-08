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
import nl.altindag.ssl.provider.FenixProvider;
import nl.altindag.ssl.provider.SSLFactoryProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class ProviderUtilsShould {

    @AfterEach
    void clearSSLFactoryProvider() {
        SSLFactoryProvider.set(null);
    }

    @Test
    void createProviderWithDefaultConfiguration() {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build();

        Provider provider = ProviderUtils.create(sslFactory);
        assertThat(provider).isInstanceOf(FenixProvider.class);
        assertThat(SSLFactoryProvider.get()).hasValue(sslFactory);
    }

    @Test
    void configureProviderWithDefaultConfiguration() {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build();

        ProviderUtils.configure(sslFactory);
        assertThat(Security.getProvider("Fenix")).isNotNull().isInstanceOf(FenixProvider.class);
        assertThat(SSLFactoryProvider.get()).hasValue(sslFactory);
        Security.removeProvider("Fenix");
    }

}
