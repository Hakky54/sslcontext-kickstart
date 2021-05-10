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

import org.junit.jupiter.api.Test;
import sun.security.util.DerOutputStream;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AccessDescription;
import sun.security.x509.AuthorityInfoAccessExtension;
import sun.security.x509.AuthorityKeyIdentifierExtension;
import sun.security.x509.URIName;
import sun.security.x509.X509CertImpl;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.cert.CertPathBuilder;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.Extension;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class CertificateUtilsIT {

    @Test
    void getRemoteCertificates() throws IOException, CertificateException {
        Map<String, List<Certificate>> certificatesFromRemote = CertificateUtils.getCertificate(
                "https://www.reddit.com/"
        );

        assertThat(certificatesFromRemote).containsKeys(
                "https://stackoverflow.com/",
                "https://github.com/",
                "https://www.linkedin.com/"
        );

        assertThat(certificatesFromRemote.get("https://stackoverflow.com/")).hasSizeGreaterThan(0);
        assertThat(certificatesFromRemote.get("https://github.com/")).hasSizeGreaterThan(0);
        assertThat(certificatesFromRemote.get("https://www.linkedin.com/")).hasSizeGreaterThan(0);
    }

    @Test
    void getRemoteCertificatesAsPem() {
        Map<String, List<String>> certificatesFromRemote = CertificateUtils.getCertificateAsPem(
                "https://stackoverflow.com/",
                "https://github.com/",
                "https://www.linkedin.com/"
        );

        assertThat(certificatesFromRemote).containsKeys(
                "https://stackoverflow.com/",
                "https://github.com/",
                "https://www.linkedin.com/"
        );

        assertThat(certificatesFromRemote.get("https://stackoverflow.com/")).hasSizeGreaterThan(0);
        assertThat(certificatesFromRemote.get("https://github.com/")).hasSizeGreaterThan(0);
        assertThat(certificatesFromRemote.get("https://www.linkedin.com/")).hasSizeGreaterThan(0);
    }

}
