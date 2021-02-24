## Http4k with Apache 5 Engine - Example SSL Client Configuration

```kotlin
import nl.altindag.ssl.SSLFactory
import nl.altindag.ssl.util.Apache5SslUtils
import org.apache.hc.client5.http.impl.classic.HttpClients
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder
import org.http4k.client.ApacheClient

class App {

    fun main(args: Array<String>) {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build()

        val socketFactory = Apache5SslUtils.toSocketFactory(sslFactory)
        val connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(socketFactory)
                .build()

        val client = ApacheClient(
                client = HttpClients.custom()
                    .setConnectionManager(connectionManager)
                    .build()
        )
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.