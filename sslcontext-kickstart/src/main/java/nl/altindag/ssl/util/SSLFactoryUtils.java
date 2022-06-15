/*
 * Copyright 2019-2022 the original author or authors.
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
import nl.altindag.ssl.exception.GenericSecurityException;

import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Function;

import static nl.altindag.ssl.util.ValidationUtils.GENERIC_EXCEPTION_MESSAGE;

/**
 * @author Hakan Altindag
 */
public final class SSLFactoryUtils {

    private static final String KEY_MANAGER_ABSENT_MESSAGE = GENERIC_EXCEPTION_MESSAGE.apply("KeyManager");
    private static final String TRUST_MANAGER_ABSENT_MESSAGE = GENERIC_EXCEPTION_MESSAGE.apply("TrustManager");

    private SSLFactoryUtils() {}

    /**
     * Reloads the ssl material for the KeyManager and / or TrustManager within the base SSLFactory if present and if it is swappable.
     * Other properties such as ciphers, protocols, secure-random, {@link javax.net.ssl.HostnameVerifier} and {@link javax.net.ssl.SSLParameters} will not be reloaded.
     */
    public static void reload(SSLFactory baseSslFactory, SSLFactory updatedSslFactory) {
        reload(baseSslFactory, updatedSslFactory, SSLFactory::getKeyManager, KeyManagerUtils::swapKeyManager, KEY_MANAGER_ABSENT_MESSAGE);
        reload(baseSslFactory, updatedSslFactory, SSLFactory::getTrustManager, TrustManagerUtils::swapTrustManager, TRUST_MANAGER_ABSENT_MESSAGE);
        SSLSessionUtils.invalidateCaches(baseSslFactory);
    }

    private static <T> void reload(SSLFactory baseSslFactory,
                                   SSLFactory updatedSslFactory,
                                   Function<SSLFactory, Optional<T>> mapper, BiConsumer<T, T> consumer,
                                   String exceptionMessage) {

        Optional<T> baseManager = mapper.apply(baseSslFactory);
        Optional<T> updatedManager = mapper.apply(updatedSslFactory);
        if (baseManager.isPresent() && updatedManager.isPresent()) {
            consumer.accept(baseManager.get(), updatedManager.get());
        } else {
            throw new GenericSecurityException(exceptionMessage);
        }
    }
}
