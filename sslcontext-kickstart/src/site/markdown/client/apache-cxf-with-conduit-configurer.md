## Apache CXF HttpClient with Conduit Configurer - Example SSL Client Configuration

```java
import nl.altindag.ssl.SSLFactory;
import org.apache.cxf.bus.CXFBusFactory;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.jaxrs.client.JAXRSClientFactoryBean;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.transport.http.HTTPConduitConfigurer;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build();

        JAXRSClientFactoryBean factory = new JAXRSClientFactoryBean();
        factory.setAddress("https://localhost:8443");
        factory.setBus(new CXFBusFactory().createBus());
        factory.getBus().setExtension((name, address, httpConduit) -> {
            TLSClientParameters tls = new TLSClientParameters();
            tls.setSSLSocketFactory(sslFactory.getSslSocketFactory());
            tls.setHostnameVerifier(sslFactory.getHostnameVerifier());
            httpConduit.setTlsClientParameters(tls);
        }, HTTPConduitConfigurer.class);

        WebClient webClient = factory.createWebClient();
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.