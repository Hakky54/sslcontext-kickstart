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

import nl.altindag.ssl.hostnameverifier.BasicHostnameVerifier;
import nl.altindag.ssl.hostnameverifier.FenixHostnameVerifier;
import nl.altindag.ssl.hostnameverifier.UnsafeHostnameVerifier;
import org.junit.jupiter.api.Test;

import javax.net.ssl.HostnameVerifier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class HostnameVerifierUtilsShould {

    @Test
    void createBasic() {
        HostnameVerifier hostnameVerifier = HostnameVerifierUtils.createBasic();

        assertThat(hostnameVerifier)
                .isNotNull()
                .isInstanceOf(BasicHostnameVerifier.class);
    }

    @Test
    void createUnsafe() {
        HostnameVerifier hostnameVerifier = HostnameVerifierUtils.createUnsafe();

        assertThat(hostnameVerifier)
                .isNotNull()
                .isInstanceOf(UnsafeHostnameVerifier.class);
    }

    @Test
    void createFenix() {
        HostnameVerifier hostnameVerifier = HostnameVerifierUtils.createFenix();

        assertThat(hostnameVerifier)
                .isNotNull()
                .isInstanceOf(FenixHostnameVerifier.class);
    }

    @Test
    void createDefault() {
        HostnameVerifier hostnameVerifier = HostnameVerifierUtils.createDefault();

        assertThat(hostnameVerifier)
                .isNotNull()
                .isInstanceOf(FenixHostnameVerifier.class);
    }

}
