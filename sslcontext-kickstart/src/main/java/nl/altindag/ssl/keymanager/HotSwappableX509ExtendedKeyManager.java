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

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static nl.altindag.ssl.util.internal.ValidationUtils.GENERIC_EXCEPTION_MESSAGE;
import static nl.altindag.ssl.util.internal.ValidationUtils.requireNotNull;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.KeyManagerUtils KeyManagerUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 *
 * @author Hakan Altindag
 */
public final class HotSwappableX509ExtendedKeyManager extends DelegatingX509ExtendedKeyManager {

    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    private final Lock readLock = readWriteLock.readLock();
    private final Lock writeLock = readWriteLock.writeLock();

    public HotSwappableX509ExtendedKeyManager(X509ExtendedKeyManager keyManager) {
        super(keyManager);
    }

    public void setKeyManager(X509ExtendedKeyManager keyManager) {
        writeLock.lock();

        try {
            this.keyManager = requireNotNull(keyManager, GENERIC_EXCEPTION_MESSAGE.apply("KeyManager"));
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        readLock.lock();

        try {
            return super.chooseClientAlias(keyType, issuers, socket);
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        readLock.lock();

        try {
            return super.chooseServerAlias(keyType, issuers, socket);
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        readLock.lock();

        try {
            return super.getPrivateKey(alias);
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        readLock.lock();

        try {
            return super.getCertificateChain(alias);
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        readLock.lock();

        try {
            return super.getClientAliases(keyType, issuers);
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        readLock.lock();

        try {
            return super.getServerAliases(keyType, issuers);
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public X509ExtendedKeyManager getInnerKeyManager() {
        readLock.lock();

        try {
            return super.getInnerKeyManager();
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine sslEngine) {
        readLock.lock();

        try {
            return super.chooseEngineClientAlias(keyTypes, issuers, sslEngine);
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine sslEngine) {
        readLock.lock();

        try {
            return super.chooseEngineServerAlias(keyType, issuers, sslEngine);
        } finally {
            readLock.unlock();
        }
    }

}
