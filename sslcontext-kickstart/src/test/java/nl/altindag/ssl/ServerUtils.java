package nl.altindag.ssl;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executor;

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
