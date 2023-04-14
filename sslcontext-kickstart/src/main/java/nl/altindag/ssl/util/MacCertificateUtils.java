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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import static nl.altindag.ssl.util.CollectorsUtils.toUnmodifiableList;

public final class MacCertificateUtils {

    private static final Path HOME_DIRECTORY = Paths.get(System.getProperty("user.home"));
    private static final List<String> KEYCHAIN_FILES = Arrays.asList(
            "/System/Library/Keychains/SystemRootCertificates.keychain",
            "/Library/Keychains/System.keychain",
            "~/Library/Keychains/login.keychain-db"
    );

    private MacCertificateUtils() {
    }

    public static List<Certificate> getCertificates() {
        ExecutorService executorService = Executors.newSingleThreadExecutor();
        StringBuilder stringBuilder = new StringBuilder();
        KEYCHAIN_FILES.stream()
                .map(MacCertificateUtils::createProcess)
                .map(process -> new StringInputStreamRunnable(process.getInputStream(), content -> stringBuilder.append(content).append(System.lineSeparator())))
                .map(executorService::submit)
                .forEach(future -> {
                    try {
                        future.get(10, TimeUnit.SECONDS);
                    } catch (ExecutionException | InterruptedException | TimeoutException e) {
                        Thread.currentThread().interrupt();
                        throw new RuntimeException(e);
                    }
                });

        executorService.shutdownNow();

        String certificateContent = stringBuilder.toString();
        return CertificateUtils.parseCertificate(certificateContent).stream()
                .distinct()
                .collect(toUnmodifiableList());
    }

    private static Process createProcess(String keychainFile) {
        try {
            return new ProcessBuilder()
                    .command("sh", "-c", "security find-certificate -a -p " + keychainFile)
                    .directory(HOME_DIRECTORY.toFile())
                    .start();
        } catch (IOException e) {
            throw new GenericIOException(e);
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
