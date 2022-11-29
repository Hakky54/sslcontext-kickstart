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

import java.security.Provider.Service;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class FenixServiceSupplierShould {

    @Test
    void createKeyManagerFactoryService() {
        FenixProvider fenixProvider = mock(FenixProvider.class);
        List<Service> keyManagerFactoryServices = FenixServiceSupplier.createKeyManagerFactoryService(fenixProvider);

        assertThat(keyManagerFactoryServices).isNotEmpty().hasSize(2);
        assertThat(keyManagerFactoryServices).extracting(Service::getAlgorithm).containsExactlyInAnyOrder("SunX509", "NewSunX509");
        assertThat(keyManagerFactoryServices).extracting(Service::getProvider).containsExactly(fenixProvider, fenixProvider);
        assertThat(keyManagerFactoryServices).extracting(Service::getType).containsExactly("KeyManagerFactory", "KeyManagerFactory");
    }

    @Test
    void createTrustManagerFactoryService() {
        FenixProvider fenixProvider = mock(FenixProvider.class);
        List<Service> trustManagerFactoryServices = FenixServiceSupplier.createTrustManagerFactoryService(fenixProvider);

        assertThat(trustManagerFactoryServices).isNotEmpty().hasSize(2);
        assertThat(trustManagerFactoryServices).extracting(Service::getAlgorithm).containsExactlyInAnyOrder("SunX509", "PKIX");
        assertThat(trustManagerFactoryServices).extracting(Service::getProvider).containsExactly(fenixProvider, fenixProvider);
        assertThat(trustManagerFactoryServices).extracting(Service::getType).containsExactly("TrustManagerFactory", "TrustManagerFactory");
    }

}
