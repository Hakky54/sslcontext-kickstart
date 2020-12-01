## Akka Http - Example SSL Client Configuration

```scala
import akka.actor.ActorSystem
import akka.http.scaladsl.model.HttpRequest
import akka.http.scaladsl.{ConnectionContext, Http}
import com.typesafe.config.ConfigFactory
import nl.altindag.client.ClientConfig
import nl.altindag.ssl.SSLFactory

object App {

    def main(args: Array[String]): Unit = {
        val sslFactory = SSLFactory.builder()
                .withIdentityMaterial("identity.jks", "secret".toCharArray)
                .withTrustMaterial("truststore.jks", "secret".toCharArray)
                .build()
        
        implicit val system = ActorSystem.create();
        
        val httpsContext = ConnectionContext.httpsClient(sslFactory.getSslContext)
        val response = Http().singleRequest(
                connectionContext = httpsContext,
                request = HttpRequest(uri = "https://localhost:8443/api/hello")
        )
    }

}

```
###### Click [here](../usage.html) to discover all other possible configurations for the SSLFactory.