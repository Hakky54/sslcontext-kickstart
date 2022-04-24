/*
 * Copyright 2019-2022 the original author or authors.
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

import java.net.URI;

import static java.util.Objects.isNull;

/**
 * @author Hakan Altindag
 */
public final class UriUtils {

    private UriUtils() {}

    public static void validate(URI uri) {
        if (isNull(uri)) {
            throw new IllegalArgumentException("Host should be present");
        }

        if (isNull(uri.getHost())) {
            throw new IllegalArgumentException(String.format("Hostname should be defined for the given input: [%s]", uri.toString()));
        }

        if (uri.getPort() == -1) {
            throw new IllegalArgumentException(String.format("Port should be defined for the given input: [%s]", uri.toString()));
        }
    }

}
