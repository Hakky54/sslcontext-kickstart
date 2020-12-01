## Http4s with Blaze Client - Example SSL Client Configuration

```scala
import cats.effect.{IO, IOApp}
import nl.altindag.ssl.SSLFactory
import org.http4s.client.blaze.BlazeClientBuilder

import scala.concurrent.ExecutionContext.Implicits.global

abstract class App extends IOApp {

    override def main(args: Array[String]): Unit = {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray)
                .withTrustMaterial("truststore.jks", "password".toCharArray)
                .build()

        val client = BlazeClientBuilder[IO](global)
                .withSslContext(sslFactory.getSslContext)
                .resource
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.