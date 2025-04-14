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
package nl.altindag.ssl.util.websocket;

import nl.altindag.ssl.exception.GenericException;
import nl.altindag.ssl.model.ClientConfig;
import nl.altindag.ssl.util.ClientRunnable;
import org.java_websocket.client.WebSocketClient;

import java.net.URI;

public class SimpleWebSocketSecureClientRunnable implements ClientRunnable {

    private WebSocketClient client;

    @Override
    public void run(ClientConfig clientConfig, URI uri) {
        client = new SimpleWebSocketSecureClient(uri);
        client.setSocketFactory(clientConfig.getSslFactory().getSslSocketFactory());
        try {
            client.connectBlocking();
        } catch (InterruptedException e) {
            throw new GenericException(e);
        }

    }

    public WebSocketClient getWebSocketClient() {
        return client;
    }

}
