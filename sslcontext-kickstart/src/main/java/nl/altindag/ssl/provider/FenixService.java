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

import java.security.Provider;
import java.util.List;
import java.util.Map;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
final class FenixService extends Provider.Service {

    /**
     * Construct a new service.
     *
     * @param provider   the provider that offers this service
     * @param type       the type of this service
     * @param algorithm  the algorithm name
     * @param className  the name of the class implementing this service
     * @param aliases    List of aliases or null if algorithm has no aliases
     * @param attributes Map of attributes or null if this implementation
     *                   has no attributes
     * @throws NullPointerException if provider, type, algorithm, or
     *                              className is null
     */
    public FenixService(Provider provider, String type, String algorithm, String className, List<String> aliases, Map<String, String> attributes) {
        super(provider, type, algorithm, className, aliases, attributes);
    }

}
