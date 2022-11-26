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

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public final class FenixProvider extends Provider {

    private static final String PROVIDER_NAME = "Fenix";
    private static final double PROVIDER_VERSION = 1.0;
    private static final String PROVIDER_INFO = "Provides various security objects";

    private static FenixProvider instance = null;

    private FenixProvider() {
        super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);
    }

    public void putService(FenixService service) {
        super.putService(service);
    }

    public static FenixProvider getInstance() {
        if (instance == null) {
            instance = new FenixProvider();
        }
        return instance;
    }

}
