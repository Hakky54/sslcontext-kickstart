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
package nl.altindag.ssl.util.internal;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Hakan Altindag
 */
class UriUtilsShould {

    @Test
    void extractHost() {
        String host = UriUtils.extractHost("https://my-first-domain.com");
        assertThat(host).isEqualTo("my-first-domain.com");
    }

    @Test
    void throwExceptionWhenInvalidUriIsProvided() {
        assertThatThrownBy(() -> UriUtils.extractHost("https://my-first-domain.com/q/h?s=^IXIC"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void throwExceptionWhenNullIsProvidedWhenValidateIsCalled() {
        assertThatThrownBy(() -> UriUtils.validate(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Host should be present");
    }

    @Test
    void throwExceptionWhenHostIsProvidedWithoutAValidPortIsProvidedWhenValidateIsCalled() {
        URI host = URI.create("https://localhost/");
        assertThatThrownBy(() -> UriUtils.validate(host))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Port should be defined for the given input: [https://localhost/]");
    }

    @Test
    void throwExceptionWhenHostIsProvidedWithoutAValidHostnameIsProvidedWhenValidateIsCalled() {
        URI host = URI.create("https:/");
        assertThatThrownBy(() -> UriUtils.validate(host))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Hostname should be defined for the given input: [https:/]");
    }

}
