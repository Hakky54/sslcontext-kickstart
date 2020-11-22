## Fuel - Example SSL Client Configuration

```kotlin
import com.github.kittinunf.fuel.core.FuelManager
import nl.altindag.sslcontext.SSLFactory

class App {
    
    fun main(args: Array<String>) {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray())
                .withTrustMaterial("truststore.jks", "password".toCharArray())
                .build()

        FuelManager.instance.hostnameVerifier = sslFactory.hostnameVerifier
        FuelManager.instance.socketFactory = sslFactory.sslSocketFactory
    }
    
}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.