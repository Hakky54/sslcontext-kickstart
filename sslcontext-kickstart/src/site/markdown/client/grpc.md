## gRPC - Example SSL Client and Server Configuration

### Server
```java
import io.grpc.Server;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyServerBuilder;
import io.netty.handler.ssl.SslContext;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.NettySslUtils;

import java.io.IOException;

public class App {

    public static void main(String[] args) throws IOException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "secret".toCharArray())
                .withTrustMaterial("truststore.jks", "secret".toCharArray())
                .withNeedClientAuthentication()
                .build();

        SslContext sslContext = GrpcSslContexts.configure(NettySslUtils.forServer(sslFactory)).build();

        Server server = NettyServerBuilder.forPort(8443)
                .sslContext(sslContext)
                .build()
                .start();
    }

}
```

### Client
```java
import io.grpc.ManagedChannel;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.SslContext;
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.NettySslUtils;

import java.io.IOException;

public class App {

    public static void main(String[] args) throws IOException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "secret".toCharArray())
                .withTrustMaterial("truststore.jks", "secret".toCharArray())
                .withDefaultTrustMaterial()
                .build();

        SslContext sslContext = GrpcSslContexts.configure(NettySslUtils.forClient(sslFactory)).build();

        ManagedChannel channel = NettyChannelBuilder.forAddress("localhost", 8443)
                .sslContext(sslContext)
                .build();
    }

}
```

###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.