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
package nl.altindag.ssl.keymanager;

import nl.altindag.ssl.util.KeyManagerUtils;
import nl.altindag.ssl.util.TrustManagerUtils;

import javax.net.ssl.X509ExtendedKeyManager;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead, use the {@link TrustManagerUtils TrustManagerUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 * <p>
 * The Inflatable KeyManager has the capability to grow with newly added identity material at any moment in time.
 * It can be added with {@link KeyManagerUtils#addIdentityMaterial(X509ExtendedKeyManager, KeyStore, char[])}
 *
 * @author Hakan Altindag
 */
public class InflatableX509ExtendedKeyManager extends HotSwappableX509ExtendedKeyManager {

    public InflatableX509ExtendedKeyManager() {
        this(KeyManagerUtils.createDummyKeyManager());
    }

    public InflatableX509ExtendedKeyManager(X509ExtendedKeyManager keyManager) {
        super(keyManager instanceof AggregatedX509ExtendedKeyManager ? keyManager : new AggregatedX509ExtendedKeyManager(Collections.singletonList(keyManager)));
    }

    public void addIdentity(X509ExtendedKeyManager keyManager) {
        writeLock.lock();

        try {
            AggregatedX509ExtendedKeyManager aggregatedKeyManager = (AggregatedX509ExtendedKeyManager) getInnerKeyManager();
            List<X509ExtendedKeyManager> innerKeyManagers = aggregatedKeyManager.getInnerKeyManagers().stream()
                    .filter(km -> !(km instanceof DummyX509ExtendedKeyManager))
                    .collect(Collectors.toCollection(ArrayList::new));
            innerKeyManagers.add(keyManager);
            setKeyManager(new AggregatedX509ExtendedKeyManager(innerKeyManagers, aggregatedKeyManager.getIdentityRoute()));
        } finally {
            writeLock.unlock();
        }
    }

}
