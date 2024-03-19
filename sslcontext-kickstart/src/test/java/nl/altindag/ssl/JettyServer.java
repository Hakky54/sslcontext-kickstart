package nl.altindag.ssl;

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
