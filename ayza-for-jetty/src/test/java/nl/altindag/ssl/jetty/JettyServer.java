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
package nl.altindag.ssl.jetty;

import nl.altindag.ssl.SSLFactory;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.ssl.SSLParameters;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JettyServer {

    private final Server server;

    public JettyServer(SSLFactory sslFactory) throws Exception {
        server = new Server();

        ServletHandler handler = new ServletHandler();
        handler.addServletWithMapping(HelloServlet.class, "/api/hello");
        server.setHandler(handler);

        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setSslContext(sslFactory.getSslContext());
        SSLParameters sslParameters = sslFactory.getSslParameters();
        sslContextFactory.setIncludeProtocols(sslParameters.getProtocols());
        sslContextFactory.setIncludeCipherSuites(sslParameters.getCipherSuites());

        ServerConnector connector = new ServerConnector(server, sslContextFactory);
        connector.setPort(8432);
        server.setConnectors(new Connector[]{connector});

        server.start();
    }

    public void stop() throws Exception {
        server.stop();
    }

    public static class HelloServlet extends HttpServlet {

        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.setContentType("text/plain");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().println("Hello!");
        }
    }

}
