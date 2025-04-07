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

import nl.altindag.ssl.SSLFactory;

import java.net.PasswordAuthentication;
import java.net.Proxy;

public class ClientConfig {

    private final SSLFactory sslFactory;
    private final Proxy proxy;
    private final PasswordAuthentication passwordAuthentication;
    private final Integer timeoutInMilliseconds;

    public ClientConfig(SSLFactory sslFactory, Proxy proxy, PasswordAuthentication passwordAuthentication, Integer timeoutInMilliseconds) {
        this.sslFactory = sslFactory;
        this.proxy = proxy;
        this.passwordAuthentication = passwordAuthentication;
        this.timeoutInMilliseconds = timeoutInMilliseconds;
    }

    public SSLFactory getSslFactory() {
        return sslFactory;
    }

    public Proxy getProxy() {
        return proxy;
    }

    public PasswordAuthentication getPasswordAuthentication() {
        return passwordAuthentication;
    }

    public Integer getTimeoutInMilliseconds() {
        return timeoutInMilliseconds;
    }

}
