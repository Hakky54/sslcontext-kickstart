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
package nl.altindag.ssl.trustmanager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import java.security.KeyStore;

import static nl.altindag.ssl.util.ValidationUtils.GENERIC_EXCEPTION_MESSAGE;
import static nl.altindag.ssl.util.ValidationUtils.requireEmpty;
import static nl.altindag.ssl.util.ValidationUtils.requireNotNull;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * This factory spi implementation is intended to use within a service for the security provider.
 *
 * @author Hakan Altindag
 */
public class RootTrustManagerFactorySpi extends TrustManagerFactorySpi {

    private static final Logger LOGGER = LoggerFactory.getLogger(RootTrustManagerFactorySpi.class);
    private static TrustManager[] trustManagers;

    @Override
    protected void engineInit(KeyStore keyStore) {
        LOGGER.debug("Ignoring provided KeyStore");
    }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) {
        LOGGER.debug("Ignoring provided ManagerFactoryParameters");
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        return trustManagers;
    }

    public static void setTrustManager(TrustManager trustManager) {
        requireEmpty(trustManagers, "TrustManager has already been configured.");
        requireNotNull(trustManager, GENERIC_EXCEPTION_MESSAGE.apply("TrustManager"));
        trustManagers = new TrustManager[]{trustManager};
    }

}