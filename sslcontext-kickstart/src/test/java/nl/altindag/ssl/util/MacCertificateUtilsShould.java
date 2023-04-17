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


import nl.altindag.ssl.exception.GenericException;
import nl.altindag.ssl.exception.GenericIOException;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.cert.Certificate;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * @author Hakan Altindag
 */
class MacCertificateUtilsShould {

    private static final String OPERATING_SYSTEM = System.getProperty("os.name").toLowerCase();

    @Test
    void getCertificate() {
        if (OPERATING_SYSTEM.contains("mac")) {
            List<Certificate> certificates = MacCertificateUtils.getCertificates();
            assertThat(certificates).isNotEmpty();
        }
    }

    @Test
    void throwsGenericIOExceptionWhenSystemProcessCannotStarted() throws IOException {
        ProcessBuilder processBuilder = mock(ProcessBuilder.class);
        when(processBuilder.command(anyString(), anyString(), anyString())).thenReturn(processBuilder);
        when(processBuilder.directory(any(File.class))).thenReturn(processBuilder);
        when(processBuilder.start()).thenThrow(new IOException("KABOOM!"));

        try (MockedStatic<MacCertificateUtils> mockedStatic = mockStatic(MacCertificateUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("createProcess".equals(method.getName()) && method.getParameterCount() == 0) {
                return processBuilder;
            } else {
                return invocation.callRealMethod();
            }
        })) {

            assertThatThrownBy(MacCertificateUtils::getCertificates)
                    .isInstanceOf(GenericIOException.class)
                    .hasMessageContaining("KABOOM!");
        }
    }

    @Test
    void waitAtMostTillTimeoutThrowsExceptionWhenSomethingWentWrong() throws ExecutionException, InterruptedException, TimeoutException {
        Future<?> future = mock(Future.class);
        when(future.get(10, TimeUnit.SECONDS)).thenThrow(new TimeoutException("KABOOM!"));

        assertThatThrownBy(() -> MacCertificateUtils.waitAtMostTillTimeout(future))
                .isInstanceOf(GenericException.class)
                .hasMessageContaining("KABOOM!");
    }

}
