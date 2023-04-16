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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static nl.altindag.ssl.util.CollectorsUtils.toUnmodifiableList;

public final class MacCertificateUtils {

    private static final Path HOME_DIRECTORY = Paths.get(System.getProperty("user.home"));
    private static final String SYSTEM_ROOT_KEYCHAIN_FILE = "/System/Library/Keychains/SystemRootCertificates.keychain";
    private static final List<String> KEYCHAIN_LOOKUP_COMMANDS = Arrays.asList("list-keychains", "default-keychain");

    private MacCertificateUtils() {
    }

    public static List<Certificate> getCertificates() {
        if (!System.getProperty("os.name").toLowerCase().contains("mac")) {
            return Collections.emptyList();
        }

        ExecutorService executorService = Executors.newSingleThreadExecutor();
        StringBuilder stringBuilder = new StringBuilder();
        getKeychainFiles(executorService).stream()
                .distinct()
                .map(MacCertificateUtils::createProcessForGettingCertificates)
                .map(process -> new StringInputStreamRunnable(process.getInputStream(), content -> stringBuilder.append(content).append(System.lineSeparator())))
                .map(executorService::submit)
                .forEach(MacCertificateUtils::waitAtMostTillTimeout);

        executorService.shutdownNow();

        String certificateContent = stringBuilder.toString();
        return CertificateUtils.parsePemCertificate(certificateContent).stream()
                .distinct()
                .collect(toUnmodifiableList());
    }

    private static List<String> getKeychainFiles(ExecutorService executorService) {
        List<String> keychainFiles = new ArrayList<>();
        keychainFiles.add(SYSTEM_ROOT_KEYCHAIN_FILE);

        KEYCHAIN_LOOKUP_COMMANDS.stream()
                .map(MacCertificateUtils::createProcessForGettingKeychainFile)
                .map(process -> new StringInputStreamRunnable(process.getInputStream(), content ->
                        Stream.of(content.split(System.lineSeparator()))
                                .map(line -> line.replace("\"", ""))
                                .map(String::trim)
                                .forEach(keychainFiles::add)))
                .map(executorService::submit)
                .forEach(MacCertificateUtils::waitAtMostTillTimeout);

        return keychainFiles;
    }

    private static Process createProcessForGettingKeychainFile(String command) {
        return createProcess("security " + command);
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
        return createProcess("security find-certificate -a -p " + keychainFilePath);
    }

    private static Process createProcess(String command) {
        try {
            return createProcess()
                    .command("sh", "-c", command)
                    .directory(HOME_DIRECTORY.toFile())
                    .start();
        } catch (IOException e) {
            throw new GenericIOException(e);
        }
    }

    /**
     * Added to make {@link MacCertificateUtils#createProcess(String)} testable
     */
    static ProcessBuilder createProcess() {
        return new ProcessBuilder();
    }

    static void waitAtMostTillTimeout(Future<?> future) {
        try {
            future.get(10, TimeUnit.SECONDS);
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            Thread.currentThread().interrupt();
            throw new GenericException(e);
        }
    }

    private static class StringInputStreamRunnable implements Runnable {
        private final InputStream inputStream;
        private final Consumer<String> consumer;

        public StringInputStreamRunnable(InputStream inputStream, Consumer<String> consumer) {
            this.inputStream = inputStream;
            this.consumer = consumer;
        }

        @Override
        public void run() {
            String content = IOUtils.getContent(inputStream);
            consumer.accept(content);
        }

    }

}
