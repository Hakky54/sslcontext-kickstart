## Http4k with Async Apache 4 Engine - Example SSL Client Configuration

```kotlin
import org.http4k.client.Apache4AsyncClient
import nl.altindag.ssl.SSLFactory

class App {

    fun main(args: Array<String>) {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build()

        val client = Apache4AsyncClient(
                client = HttpAsyncClients.custom()
                    .setSSLContext(sslFactory.sslContext)
                    .setSSLHostnameVerifier(sslFactory.hostnameVerifier)
                    .build()
        )
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.