/*
 * Copyright 2019-2021 the original author or authors.
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

package nl.altindag.ssl.model;

import java.security.KeyStore;

/**
 * @author Hakan Altindag
 */
public final class KeyStoreHolder {

    private final KeyStore keyStore;
    private final char[] keyStorePassword;
    private char[] keyPassword = {};

    public KeyStoreHolder(KeyStore keyStore, char[] keyStorePassword) {
        this.keyStore = keyStore;
        this.keyStorePassword = keyStorePassword;
    }

    public KeyStoreHolder(KeyStore keyStore, char[] keyStorePassword, char[] keyPassword) {
        this.keyStore = keyStore;
        this.keyStorePassword = keyStorePassword;
        this.keyPassword = keyPassword;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public char[] getKeyStorePassword() {
        return keyStorePassword;
    }

    public char[] getKeyPassword() {
        return keyPassword;
    }

}
