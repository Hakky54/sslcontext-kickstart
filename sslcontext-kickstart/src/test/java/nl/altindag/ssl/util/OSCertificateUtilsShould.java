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


import nl.altindag.ssl.IOTestUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class OSCertificateUtilsShould {

    @Test
    void loadCertificateIgnoresInvalidFiles() throws IOException {
        Path path = IOTestUtils.copyFileToHomeDirectory("pem/", "invalid.pem");
        List<Certificate> certificates = OSCertificateUtils.loadCertificate(path);
        assertThat(certificates).isEmpty();
        Files.delete(path);
    }

    @Test
    void loadCertificateReadsValidFiles() throws IOException {
        Path path = IOTestUtils.copyFileToHomeDirectory("pem/", "badssl-certificate.pem");
        List<Certificate> certificates = OSCertificateUtils.loadCertificate(path);
        assertThat(certificates).isNotEmpty();
        Files.delete(path);
    }

}
