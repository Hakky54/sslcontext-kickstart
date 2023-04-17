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

import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * @author Hakan Altindag
 */
public final class SSLFactoryUtils {

    private SSLFactoryUtils() {}

    /**
     * Reloads the ssl material for the KeyManager and / or TrustManager within the base SSLFactory if present and if it is swappable.
     * Other properties such as ciphers, protocols, secure-random, {@link javax.net.ssl.HostnameVerifier} and {@link javax.net.ssl.SSLParameters} will not be reloaded.
     */
    public static void reload(SSLFactory baseSslFactory, SSLFactory updatedSslFactory) {
        reload(baseSslFactory, updatedSslFactory, true);
    }

    /**
     * Reloads the ssl material for the KeyManager and / or TrustManager within the base SSLFactory if present and if it is swappable.
     * Other properties such as ciphers, protocols, secure-random, {@link javax.net.ssl.HostnameVerifier} and {@link javax.net.ssl.SSLParameters} will not be reloaded.
     */
    public static void reload(SSLFactory baseSslFactory, SSLFactory updatedSslFactory, boolean shouldInvalidateCaches) {
        reload(baseSslFactory, updatedSslFactory, SSLFactory::getKeyManager, KeyManagerUtils::swapKeyManager);
        reload(baseSslFactory, updatedSslFactory, SSLFactory::getTrustManager, TrustManagerUtils::swapTrustManager);
        if (shouldInvalidateCaches) {
            SSLSessionUtils.invalidateCaches(baseSslFactory);
        }
    }

    private static <T> void reload(SSLFactory baseSslFactory,
                                   SSLFactory updatedSslFactory,
                                   Function<SSLFactory, Optional<T>> mapper,
                                   BiConsumer<T, T> consumer) {

        Optional<T> baseManager = mapper.apply(baseSslFactory);
        Optional<T> updatedManager = mapper.apply(updatedSslFactory);
        if (baseManager.isPresent() && updatedManager.isPresent()) {
            consumer.accept(baseManager.get(), updatedManager.get());
        }
    }

}
