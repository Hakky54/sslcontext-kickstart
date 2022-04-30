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
package nl.altindag.ssl.keymanager;

import org.junit.jupiter.api.Test;

import javax.net.ssl.X509ExtendedKeyManager;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class DummyX509ExtendedKeyManagerShould {

    private final X509ExtendedKeyManager victim = DummyX509ExtendedKeyManager.getInstance();

    @Test
    void getClientAliases() {
        assertThat(victim.getClientAliases(null, null)).isNull();
    }

    @Test
    void chooseClientAlias() {
        assertThat(victim.chooseClientAlias(null, null, null)).isNull();
    }

    @Test
    void chooseEngineClientAlias() {
        assertThat(victim.chooseEngineClientAlias(null, null, null)).isNull();
    }

    @Test
    void getServerAliases() {
        assertThat(victim.getServerAliases(null, null)).isNull();
    }

    @Test
    void chooseServerAlias() {
        assertThat(victim.chooseServerAlias(null, null, null)).isNull();
    }

    @Test
    void chooseEngineServerAlias() {
        assertThat(victim.chooseEngineServerAlias(null, null, null)).isNull();
    }

    @Test
    void getCertificateChain() {
        assertThat(victim.getCertificateChain(null)).isNull();
    }

    @Test
    void getPrivateKey() {
        assertThat(victim.getPrivateKey(null)).isNull();
    }

}
