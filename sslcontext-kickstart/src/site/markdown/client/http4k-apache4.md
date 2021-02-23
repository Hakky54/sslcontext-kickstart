## Http4k with Apache 4 Engine - Example SSL Client Configuration

```kotlin
import nl.altindag.ssl.SSLFactory
import nl.altindag.ssl.util.Apache4SslUtils
import org.apache.http.impl.client.HttpClients
import org.http4k.client.Apache4Client

class App {

    fun main(args: Array<String>) {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build()

        val client = Apache4Client(
                client = HttpClients.custom()
                    .setSSLSocketFactory(Apache4SslUtils.toSocketFactory(sslFactory))
                    .build()
        )
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.