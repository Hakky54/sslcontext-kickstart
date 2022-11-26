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
package nl.altindag.ssl.provider;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class FenixServiceSupplierShould {

    @Test
    void createKeyManagerFactoryService() {
        FenixProvider fenixProvider = mock(FenixProvider.class);
        FenixService keyManagerFactoryService = FenixServiceSupplier.createKeyManagerFactoryService(fenixProvider);

        assertThat(keyManagerFactoryService).isNotNull();
        assertThat(keyManagerFactoryService.getAlgorithm()).isEqualTo("PKIX");
        assertThat(keyManagerFactoryService.getProvider()).isEqualTo(fenixProvider);
        assertThat(keyManagerFactoryService.getType()).isEqualTo("KeyManagerFactory");
    }

    @Test
    void createTrustManagerFactoryService() {
        FenixProvider fenixProvider = mock(FenixProvider.class);
        FenixService trustManagerFactoryService = FenixServiceSupplier.createTrustManagerFactoryService(fenixProvider);

        assertThat(trustManagerFactoryService).isNotNull();
        assertThat(trustManagerFactoryService.getAlgorithm()).isEqualTo("PKIX");
        assertThat(trustManagerFactoryService.getProvider()).isEqualTo(fenixProvider);
        assertThat(trustManagerFactoryService.getType()).isEqualTo("TrustManagerFactory");
    }

}
