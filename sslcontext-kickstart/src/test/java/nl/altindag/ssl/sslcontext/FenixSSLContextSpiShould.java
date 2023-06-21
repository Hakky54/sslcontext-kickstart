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
package nl.altindag.ssl.sslcontext;

import nl.altindag.log.LogCaptor;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class FenixSSLContextSpiShould {

    @Test
    void ignoreProvidedParametersAndDebugLogWhenEngineInitIsBeingCalled() {
        LogCaptor logCaptor = LogCaptor.forClass(FenixSSLContextSpi.class);

        FenixSSLContextSpi sslContextSpi = new FenixSSLContextSpi(null, null);
        sslContextSpi.engineInit(null, null, null);

        assertThat(logCaptor.getDebugLogs())
                .containsExactly("The provided parameters are being ignored as the SSLContext has already been initialized");
    }

}
