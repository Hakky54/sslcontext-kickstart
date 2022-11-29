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

import nl.altindag.ssl.keymanager.RootKeyManagerFactorySpi;
import nl.altindag.ssl.trustmanager.RootTrustManagerFactorySpi;

import java.security.Provider;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public final class FenixServiceSupplier {

    private FenixServiceSupplier() {
    }

    public static List<Provider.Service> createKeyManagerFactoryService(Provider provider) {
        Map<String, List<String>> algorithmToAliases = new HashMap<>();
        algorithmToAliases.put("SunX509", null);
        algorithmToAliases.put("NewSunX509", Collections.singletonList("PKIX"));

        return algorithmToAliases.entrySet().stream()
                .map(entry -> new FenixService(provider,
                        "KeyManagerFactory",
                        entry.getKey(),
                        RootKeyManagerFactorySpi.class.getName(),
                        entry.getValue(),
                        null))
                .collect(Collectors.toList());
    }

    public static List<Provider.Service> createTrustManagerFactoryService(Provider provider) {
        Map<String, List<String>> algorithmToAliases = new HashMap<>();
        algorithmToAliases.put("SunX509", null);
        algorithmToAliases.put("PKIX", Arrays.asList("SunPKIX", "X509", "X.509"));

        return algorithmToAliases.entrySet().stream()
                .map(entry -> new FenixService(provider,
                        "TrustManagerFactory",
                        entry.getKey(),
                        RootTrustManagerFactorySpi.class.getName(),
                        entry.getValue(),
                        null))
                .collect(Collectors.toList());
    }

}
