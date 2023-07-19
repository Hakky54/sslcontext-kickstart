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
package nl.altindag.ssl.model;

import javax.net.ssl.SSLSession;

/**
 * @author Hakan Altindag
 */
public final class HostnameVerifierParameters {

    private final String hostname;
    private final SSLSession session;

    public HostnameVerifierParameters(String hostname, SSLSession session) {
        this.hostname = hostname;
        this.session = session;
    }

    public String getHostname() {
        return hostname;
    }

    public SSLSession getSession() {
        return session;
    }

}
