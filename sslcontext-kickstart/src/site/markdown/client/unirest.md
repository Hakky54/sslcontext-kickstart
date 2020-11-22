## Unirest - Example SSL Client Configuration

```java
import kong.unirest.Unirest;
import nl.altindag.sslcontext.SSLFactory;

public class App {

    public static void main(String[] args) throws Exception {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        Unirest.primaryInstance()
                .config()
                .sslContext(sslFactory.getSslContext())
                .protocols(sslFactory.getSslParameters().getProtocols())
                .ciphers(sslFactory.getSslParameters().getCipherSuites())
                .hostnameVerifier(sslFactory.getHostnameVerifier());
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.