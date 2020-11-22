## Dispatch Reboot- Example SSL Client Configuration

```scala
import dispatch.Http
import nl.altindag.sslcontext.SSLFactory
import nl.altindag.sslcontext.util.NettySslContextUtils

object App {

    def main(args: Array[String]): Unit = {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray)
                .withTrustMaterial("truststore.jks", "password".toCharArray)
                .build()
        
        val sslContext = NettySslContextUtils.forClient(sslFactory).build
        val client = Http.withConfiguration(builder => builder.setSslContext(sslContext))
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.