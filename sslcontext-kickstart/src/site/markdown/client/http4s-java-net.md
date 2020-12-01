## Http4s with Java Net Client - Example SSL Client Configuration

```scala
import cats.effect.{Blocker, IOApp, Resource}
import nl.altindag.ssl.SSLFactory
import org.http4s.client.JavaNetClientBuilder

import scala.concurrent.ExecutionContext.Implicits.global

abstract class App extends IOApp {

    override def main(args: Array[String]): Unit = {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "password".toCharArray)
                .withTrustMaterial("truststore.jks", "password".toCharArray)
                .build()

        var client = JavaNetClientBuilder[IO](Blocker.liftExecutionContext(global))
                .withSslSocketFactory(sslFactory.getSslSocketFactory)
                .withHostnameVerifier(sslFactory.getHostnameVerifier)
                .resource
    }

}
```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.