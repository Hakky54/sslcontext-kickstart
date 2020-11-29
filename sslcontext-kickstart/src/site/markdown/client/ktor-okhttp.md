## Ktor with OkHttp Engine - Example SSL Client Configuration

```kotlin
import io.ktor.client.*
import io.ktor.client.engine.android.*
import nl.altindag.sslcontext.SSLFactory

class App {

    fun main(args: Array<String>) {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build()

        val httpClient = HttpClient(OkHttp) {
            engine {
                config {
                    sslSocketFactory(sslFactory.sslSocketFactory, sslFactory.trustManager.orElseThrow())
                    hostnameVerifier(sslFactory.hostnameVerifier)
                }
            }
        }
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.