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
package nl.altindag.ssl;

import io.javalin.Javalin;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;

/**
 * @author Hakan Altindag
 */
public final class ServerUtils {

    private ServerUtils() {
    }

    public static Javalin createServer(SSLFactory sslFactory) {
        return createServer(sslFactory, 8443, "Hello World");
    }

    public static Javalin createServer(SSLFactory sslFactory, int port, String responseBody) {
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setSslContext(sslFactory.getSslContext());
        sslContextFactory.setNeedClientAuth(true);

        Javalin app = Javalin.create(config -> config.jetty.server(() -> {
            Server server = new Server();
            ServerConnector sslConnector = new ServerConnector(server, sslContextFactory);
            sslConnector.setPort(port);
            server.setConnectors(new Connector[]{sslConnector});
            return server;
        })).start();

        app.get("/api/hello", ctx -> ctx.result(responseBody));
        return app;
    }

}
