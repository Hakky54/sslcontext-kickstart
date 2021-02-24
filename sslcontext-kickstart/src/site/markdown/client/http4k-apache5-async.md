## Http4k with Async Apache 5 Engine - Example SSL Client Configuration

```kotlin
import nl.altindag.ssl.SSLFactory
import nl.altindag.ssl.util.Apache5SslUtils
import org.apache.hc.client5.http.impl.async.HttpAsyncClients
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder
import org.http4k.client.ApacheAsyncClient

class App {

    fun main(args: Array<String>) {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build()

        val connectionManager = PoolingAsyncClientConnectionManagerBuilder.create()
                .setTlsStrategy(Apache5SslUtils.toTlsStrategy(sslFactory))
                .build()

        val client = ApacheAsyncClient(
                client = HttpAsyncClients.custom()
                    .setConnectionManager(connectionManager)
                    .build()
        )
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.