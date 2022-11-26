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

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public final class FenixServiceSupplier {

    private FenixServiceSupplier() {
    }

    public static FenixService createKeyManagerFactoryService(Provider provider) {
        return new FenixService(provider,
                "KeyManagerFactory",
                "PKIX",
                RootKeyManagerFactorySpi.class.getName(),
                Collections.singletonList("SunX509"),
                Collections.emptyMap());
    }

    public static FenixService createTrustManagerFactoryService(Provider provider) {
        return new FenixService(provider,
                "TrustManagerFactory",
                "PKIX",
                RootTrustManagerFactorySpi.class.getName(),
                Arrays.asList("X.509", "X509", "SunPKIX", "SunX509"),
                Collections.emptyMap());
    }

}
