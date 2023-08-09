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
import nl.altindag.ssl.util.internal.IOUtils;

import java.io.IOException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static nl.altindag.ssl.util.OperatingSystem.MAC;

/**
 * @author Hakan Altindag
 */
final class MacCertificateUtils {

    private static final String SECURITY_EXECUTABLE = "security";
    private static final String SYSTEM_ROOT_KEYCHAIN_FILE = "/System/Library/Keychains/SystemRootCertificates.keychain";
    private static final List<String> KEYCHAIN_LOOKUP_COMMANDS = Arrays.asList("list-keychains", "default-keychain");

    private static final String EMPTY = "";
    private static final String SPACE = " ";
    private static final String DOUBLE_QUOTES = "\"";

    private MacCertificateUtils() {
    }

    static List<Certificate> getCertificates() {
        if (OperatingSystem.get() != MAC) {
            return Collections.emptyList();
        }

        String certificateContent = getKeychainFiles().stream()
                .distinct()
                .map(MacCertificateUtils::createProcessForGettingCertificates)
                .map(Process::getInputStream)
                .map(IOUtils::getContent)
                .collect(Collectors.joining(System.lineSeparator()));

        return CertificateUtils.parsePemCertificate(certificateContent);
    }

    private static List<String> getKeychainFiles() {
        List<String> keychainFiles = new ArrayList<>();
        keychainFiles.add(SYSTEM_ROOT_KEYCHAIN_FILE);

        KEYCHAIN_LOOKUP_COMMANDS.stream()
                .map(MacCertificateUtils::createProcessForGettingKeychainFile)
                .map(Process::getInputStream)
                .map(IOUtils::getContent)
                .flatMap(content -> Stream.of(content.split(System.lineSeparator()))
                        .map(line -> line.replace(DOUBLE_QUOTES, EMPTY))
                        .map(String::trim))
                .forEach(keychainFiles::add);

        return keychainFiles;
    }

    private static Process createProcessForGettingKeychainFile(String command) {
        return createProcess(SECURITY_EXECUTABLE + SPACE + command);
    }

    /**
     * Uses a mac command while using bash to get the certificates from keychain with: security find-certificate
     * <p>
     * <pre>
     * It uses the following CLI options:
     *     -a Find all matching certificates, not just the first one
     *     -p Output certificate in pem format
     * </pre>
     */
    private static Process createProcessForGettingCertificates(String keychainFilePath) {
        String command = String.format("%s find-certificate -a -p %s", SECURITY_EXECUTABLE, keychainFilePath);
        return createProcess(command);
    }

    private static Process createProcess(String command) {
        try {
            return Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            throw new GenericIOException(e);
        }
    }

}
