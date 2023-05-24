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
package nl.altindag.ssl.pem;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import nl.altindag.ssl.SSLFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executor;

/**
 * @author Hakan Altindag
 */
public final class ServerUtils {

    private ServerUtils() {}

    public static HttpsServer createServer(int port, SSLFactory sslFactory, Executor executor, String payload) throws IOException {
        InetSocketAddress socketAddress = new InetSocketAddress(port);
        HttpsServer server = HttpsServer.create(socketAddress, 0);
        server.setExecutor(executor);
        server.setHttpsConfigurator(new HttpsConfigurator(sslFactory.getSslContext()) {
            @Override
            public void configure(HttpsParameters params) {
                params.setSSLParameters(sslFactory.getSslParameters());
            }
        });

        class HelloWorldController implements HttpHandler {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                try (OutputStream responseBody = exchange.getResponseBody()) {

                    exchange.getResponseHeaders().set("Content-Type", "text/plain");

                    exchange.sendResponseHeaders(200, payload.length());
                    responseBody.write(payload.getBytes(StandardCharsets.UTF_8));
                }
            }
        }
        server.createContext("/api/hello", new HelloWorldController());
        return server;
    }

}
