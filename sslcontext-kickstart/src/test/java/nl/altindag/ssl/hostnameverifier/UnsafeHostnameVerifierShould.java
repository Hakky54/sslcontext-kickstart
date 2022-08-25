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
package nl.altindag.ssl.hostnameverifier;

import org.junit.jupiter.api.Test;

import javax.net.ssl.HostnameVerifier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class UnsafeHostnameVerifierShould {

    @Test
    void verifyReturnsAlwaysTrue() {
        HostnameVerifier hostnameVerifier = UnsafeHostNameVerifier.getInstance();

        boolean verify = hostnameVerifier.verify("some-host", null);
        assertThat(verify).isTrue();
    }

}
