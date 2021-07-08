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

package nl.altindag.ssl.util;

import nl.altindag.ssl.exception.GenericIOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class IOUtilsShould {

    @Test
    void getContent() {
        ByteArrayInputStream inputStream = new ByteArrayInputStream("Hello".getBytes());
        String content = IOUtils.getContent(inputStream);
        assertThat(content).isEqualTo("Hello");
    }

    @Test
    void getContentThrowsGenericIOExceptionWhenStreamFailsToClose() throws IOException {
        ByteArrayInputStream inputStream = Mockito.spy(new ByteArrayInputStream("Hello".getBytes()));
        doThrow(new IOException("Could not read the content")).when(inputStream).close();

        assertThatThrownBy(() -> IOUtils.getContent(inputStream))
                .isInstanceOf(GenericIOException.class)
                .hasRootCauseMessage("Could not read the content");
    }

    @Test
    void closeSilentlyDoesNotThrowExceptionWhenCloseFails() throws IOException {
        ByteArrayInputStream inputStream = Mockito.spy(new ByteArrayInputStream("Hello".getBytes()));
        doThrow(new IOException("Could not read the content")).when(inputStream).close();

        assertThatCode(() -> IOUtils.closeSilently(inputStream))
                .doesNotThrowAnyException();
    }

    @Test
    void createCopy() {
        ByteArrayInputStream inputStream = new ByteArrayInputStream("Hello".getBytes());
        ByteArrayOutputStream copy = IOUtils.createCopy(inputStream);

        String content = IOUtils.getContent(new ByteArrayInputStream(copy.toByteArray()));
        assertThat(content).isEqualTo("Hello");
    }

    @Test
    void createCopyThrowsGenericIOExceptionWhenReadingFails() throws IOException {
        ByteArrayInputStream inputStream = Mockito.spy(new ByteArrayInputStream("Hello".getBytes()));
        doThrow(new IOException("Could not read the content")).when(inputStream).read(any());

        assertThatThrownBy(() -> IOUtils.createCopy(inputStream))
                .isInstanceOf(GenericIOException.class)
                .hasRootCauseMessage("Could not read the content");
    }

}
