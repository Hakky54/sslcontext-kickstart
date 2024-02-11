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

import nl.altindag.ssl.SSLFactory;

import java.util.Optional;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * @author Hakan Altindag
 */
public final class SSLFactoryProvider {

    private static SSLFactoryProvider INSTANCE;

    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    private final Lock readLock = readWriteLock.readLock();
    private final Lock writeLock = readWriteLock.writeLock();
    private SSLFactory sslFactory;


    private SSLFactoryProvider() {

    }

    public static void set(SSLFactory sslFactory) {
        SSLFactoryProvider instance = getInstance();
        instance.writeLock.lock();

        try {
            instance.sslFactory = sslFactory;
        } finally {
            instance.writeLock.unlock();
        }
    }

    public static Optional<SSLFactory> get() {
        SSLFactoryProvider instance = getInstance();
        instance.readLock.lock();

        try {
            return Optional.ofNullable(instance.sslFactory);
        } finally {
            instance.readLock.unlock();
        }
    }

    private static SSLFactoryProvider getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new SSLFactoryProvider();
        }
        return INSTANCE;
    }

}