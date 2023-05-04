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

import javax.net.ssl.SSLEngine;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.AbstractMap;
import java.util.Map;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public final class HostUtils {

    private HostUtils() {}

    public static Map.Entry<String, Integer> extractHostAndPort(Socket socket) {
        InetSocketAddress address = (InetSocketAddress) socket.getRemoteSocketAddress();
        return new AbstractMap.SimpleImmutableEntry<>(address.getHostName(), address.getPort());
    }

    public static Map.Entry<String, Integer> extractHostAndPort(SSLEngine sslEngine) {
        return new AbstractMap.SimpleImmutableEntry<>(sslEngine.getPeerHost(), sslEngine.getPeerPort());
    }

}
