## Usage

### Definitions
* Identity: A KeyStore which holds the key pair also known as private and public key
* TrustStore: A KeyStore containing one or more certificates also known as public key. This KeyStore contains a list of trusted certificates
* One way authentication (also known as one way tls, one way ssl): Https connection where the client validates the certificate of the counter party
* Two way authentication (also known as two way tls, two way ssl, mutual authentication): Https connection where the client as well as the counter party validates the certificate, also known as mutual authentication
  
### SSLFactory configurations
SSLFactory can be enriched with additional configuration with the fluent api.
It has already built-in default values for SecureRandom, HostnameVerifier, Encryption protocol, but can be overridden if required, see below for examples and additional configurations.

One way authentication with custom trustStore 
```text
SSLFactory.builder()
          .withTrustStoreMaterial(trustStore, trustStorePassword)
          .build();
```

One way authentication while trusting all certificates without validation, not recommended to use at production!
```text
SSLFactory.builder()
          .withTrustingAllCertificatesWithoutValidation()
          .build();
```

One way authentication with specific encryption protocol version, custom secure random and option to validate the hostname within the request against the SAN field of a certificate.
If you are using java 11 or newer, than you are also able to use TLSv1.3 as encryption protocol. Just provide `TLSv1.3` as protocol argument and it will work out-of-the-box.
```text
SSLFactory.builder()
          .withTrustStoreMaterial(trustStore, trustStorePassword)
          .withHostnameVerifier(hostnameVerifier)
          .withSecureRandom(secureRandom)
          .withProtocol("TLSv1.2")
          .build();
```

Two way authentication with custom trustStore, hostname verifier and encryption protocol version
```text
SSLFactory.builder()
          .withIdentityMaterial(identity, identityPassword)
          .withTrustStoreMaterial(trustStore, trustStorePassword)
          .withHostnameVerifier(hostnameVerifier)
          .withProtocol("TLSv1.2")
          .build();
```

Support for using multiple identity materials and trust materials 
```text
SSLFactory.builder()
          .withIdentityMaterial(identityA, identityPasswordA)
          .withIdentityMaterial(identityB, identityPasswordB)
          .withIdentityMaterial(identityC, identityPasswordC)
          .withTrustStoreMaterial(trustStoreA, trustStorePasswordA)
          .withTrustStoreMaterial(trustStoreB, trustStorePasswordB)
          .withTrustStoreMaterial(trustStoreC, trustStorePasswordC)
          .withTrustStoreMaterial(trustStoreD, trustStorePasswordD)
          .withProtocol("TLSv1.2")
          .build();
```

Support for using X509ExtendedKeyManager and X509ExtendedTrustManager
```text
X509ExtendedKeyManager keyManager = ...
X509ExtendedTrustManager trustManager = ...

SSLFactory.builder()
          .withIdentityMaterial(keyManager)
          .withTrustStoreMaterial(trustManager)
          .build();
```

### Additional mappers for specific libraries
Some http clients relay on different ssl classes from third parties and require mapping from SSLFactory to those libraries.
Below you will find the maven dependency which will provide the mapping and also the SSLFactory library.
When using one of the below libraries, it is not required to also explicitly include sslcontext-kickstart.

#### Netty
Some know http clients which relay on netty libraries are: [Spring WebFlux WebClient Netty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html), [Async Http Client](https://github.com/AsyncHttpClient/async-http-client) and [Dispatch Reboot Http Client](https://github.com/dispatch/reboot).
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart-for-netty</artifactId>
</dependency>
```
Example setup for Spring WebClient with Netty:
```java
import io.netty.handler.ssl.SslContext;
import nl.altindag.sslcontext.SSLFactory;
import nl.altindag.sslcontext.util.NettySslContextUtils;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLException;

public class App {
    
    public static void main(String[] args) throws SSLException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultJdkTrustStore()
                .build();

        SslContext sslContext = NettySslContextUtils.forClient(sslFactory).build();
        HttpClient httpClient = HttpClient.create()
                .secure(sslSpec -> sslSpec.sslContext(sslContext));

        WebClient webClient = WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }

}
```

#### Jetty
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart-for-jetty</artifactId>
</dependency>
```
Example setup for [Spring WebFlux WebClient Jetty](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html):
```java
import nl.altindag.sslcontext.SSLFactory;
import nl.altindag.sslcontext.util.JettySslContextUtils;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.http.client.reactive.JettyClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultJdkTrustStore()
                .build();
        
        SslContextFactory.Client sslContextFactory = JettySslContextUtils.forClient(sslFactory);
        HttpClient httpClient = new HttpClient(sslContextFactory);

        WebClient webClient = WebClient.builder()
                .clientConnector(new JettyClientHttpConnector(httpClient))
                .build();
    }

}
```

#### Apache
Apache Http Client works with javax.net.ssl.SSLContext, so an additional mapping to their library is not required, [see here](./index.html).
However it is still possible to configure the http client with their custom configuration class. you can find below an example configuration for that use case:
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart-for-apache</artifactId>
</dependency>
```
```java
import nl.altindag.sslcontext.SSLFactory;
import nl.altindag.sslcontext.util.ApacheSslContextUtils;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultJdkTrustStore()
                .build();

        LayeredConnectionSocketFactory socketFactory = ApacheSslContextUtils.toLayeredConnectionSocketFactory(sslFactory);

        HttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(socketFactory)
                .build();
    }

}
```