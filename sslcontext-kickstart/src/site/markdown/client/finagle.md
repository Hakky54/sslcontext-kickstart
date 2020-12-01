## Twitter Finagle - Example SSL Client Configuration

```scala
import java.net.URI
import com.twitter.finagle.Http
import nl.altindag.ssl.SSLFactory

class App {

    def main(args: Array[String]): Unit = {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray)
                .withTrustMaterial("truststore.jks", "password".toCharArray)
                .build()
        
        val uri = new URI("https://localhost:8443/api/hello")
        val service = Http.client.withTransport.tls(sslFactory.getSslContext)
                .newService(uri.getHost + ":" + uri.getPort)
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.