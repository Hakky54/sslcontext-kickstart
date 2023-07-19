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
package nl.altindag.ssl.hostnameverifier;

import nl.altindag.ssl.model.HostnameVerifierParameters;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import java.util.function.Predicate;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.HostnameVerifierUtils HostnameVerifierUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 * </p>
 *
 * @author Hakan Altindag
 */
public final class EnhanceableHostnameVerifier implements HostnameVerifier {

    private final HostnameVerifier baseHostnameVerifier;
    private final Predicate<HostnameVerifierParameters> hostnameVerifierParametersValidator;

    public EnhanceableHostnameVerifier(HostnameVerifier baseHostnameVerifier, Predicate<HostnameVerifierParameters> hostnameVerifierParametersValidator) {
        this.baseHostnameVerifier = baseHostnameVerifier;
        this.hostnameVerifierParametersValidator = hostnameVerifierParametersValidator;
    }

    @Override
    public boolean verify(String hostname, SSLSession session) {
        HostnameVerifierParameters hostnameVerifierParameters = new HostnameVerifierParameters(hostname, session);
        if (hostnameVerifierParametersValidator.test(hostnameVerifierParameters)) {
            return true;
        }

        return baseHostnameVerifier.verify(hostname, session);
    }
}
