## Twitter Finagle Featherbed - Example SSL Client Configuration

```scala
import java.net.{URI, URL}
import java.nio.charset.{Charset, StandardCharsets}

import com.twitter.finagle.Http
import nl.altindag.sslcontext.SSLFactory

class App {

    def main(args: Array[String]): Unit = {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build()
        
        val client = new SecureFeatherbedClient(sslFactory, new URI("https://localhost:8443/api/hello").toURL, StandardCharsets.UTF_8)
    }

}

class SecureFeatherbedClient(sslFactory: SSLFactory, val baseUrl: URL, val charset: Charset) extends featherbed.Client(baseUrl, charset) {

    override protected def clientTransform(client: Http.Client): Http.Client = {
        super.clientTransform(client)
             .withTransport
             .tls(sslFactory.getSslContext)
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.