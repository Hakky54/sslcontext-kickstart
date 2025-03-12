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


import nl.altindag.ssl.exception.GenericIOException;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.cert.Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
class MacCertificateUtilsShould {

    private static final String OS_NAME = System.getProperty("os.name");

    @Test
    void getCertificate() {
        if (OS_NAME.toLowerCase().contains("mac")) {
            List<Certificate> certificates = MacCertificateUtils.getInstance().getCertificates();
            assertThat(certificates).isNotEmpty();
        }
    }

    @Test
    void notContainLoginKeychain() {
        if (OS_NAME.toLowerCase().contains("mac")) {
            List<String> keychainFiles = MacCertificateUtils.getKeychainFiles();
            assertThat(keychainFiles).isNotEmpty();

            for (String keychainFile : keychainFiles) {
                assertThat(keychainFile).doesNotEndWith("/Library/Keychains/login.keychain-db");
            }
        }
    }

    @Test
    void throwsGenericIOExceptionWhenSystemProcessCannotStarted() throws IOException {
        System.setProperty("os.name", "Mac OS X");

        Runtime runtime = mock(Runtime.class);
        when(runtime.exec(anyString())).thenThrow(new IOException("KABOOM!"));

        try (MockedStatic<Runtime> mockedStatic = mockStatic(Runtime.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getRuntime".equals(method.getName())) {
                return runtime;
            } else {
                return invocation.callRealMethod();
            }
        })) {

            assertThatThrownBy(() -> MacCertificateUtils.getInstance().getCertificates())
                    .isInstanceOf(GenericIOException.class)
                    .hasMessageContaining("KABOOM!");
        }

        resetOsName();
    }

    private void resetOsName() {
        System.setProperty("os.name", OS_NAME);
    }

}
