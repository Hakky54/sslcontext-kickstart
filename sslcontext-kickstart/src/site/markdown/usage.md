## Usage

### SSLFactory configurations
SSLFactory can be enriched with additional configuration with the fluent api.
It has already built-in default values for SecureRandom, HostnameVerifier, Encryption protocol, but can be overridden if required, see below for examples and additional configurations.

##### Loading keystore and truststore from the classpath
```text
SSLFactory.builder()
          .withIdentityMaterial("identity.jks", "password".toCharArray())
          .withTrustMaterial("truststore.jks", "password".toCharArray())
          .build();
```

##### Loading keystore and trust store from anywhere on the filesystem
```text
SSLFactory.builder()
          .withIdentityMaterial(Paths.get("/path/to/your/identity.jks"), "password".toCharArray())
          .withTrustMaterial(Paths.get("/path/to/your/truststore.jks"), "password".toCharArray())
          .build();
```

##### Trusting all certificates without validation, not recommended to use at production!
```text
SSLFactory.builder()
          .withTrustingAllCertificatesWithoutValidation()
          .build();
```

##### Loading JDK and OS trusted certificates
```text
SSLFactory.builder()
          .withDefaultTrustMaterial()
          .withSystemTrustMaterial()
          .build();
```

##### Using specific protocols, ciphers with custom secure random and hostname verifier
If you are using java 11 or newer, than you are also able to use TLSv1.3 as encryption protocol by default.
```text
SSLFactory.builder()
          .withDefaultTrustMaterial()
          .withProtocols("TLSv1.3", "TLSv1.2")
          .withCiphers("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384")
          .withHostnameVerifier(hostnameVerifier)
          .withSecureRandom(secureRandom)
          .build();
```

##### Support for using multiple identity materials and trust materials
```text
SSLFactory.builder()
          .withIdentityMaterial("identity-1.jks", password)
          .withIdentityMaterial("identity-2.jks", password)
          .withIdentityMaterial("identity-3.jks", password)
          .withIdentityMaterial("identity-4.jks", password)
          .withTrustMaterial("truststore-1.jks", password)
          .withTrustMaterial("truststore-2.jks", password)
          .withTrustMaterial("truststore-3.jks", password)
          .withTrustMaterial("truststore-4.jks", password)
          .build();
```

##### Support for using X509ExtendedKeyManager and X509ExtendedTrustManager
```text
X509ExtendedKeyManager keyManager = ...
X509ExtendedTrustManager trustManager = ...

SSLFactory.builder()
          .withIdentityMaterial(keyManager)
          .withTrustMaterial(trustManager)
          .build();
```

##### Support for using PrivateKey and Certificates
```text
PrivateKey privateKey = ...
char[] privateKeyPassword = ...
Certificate[] certificateChain = ...

Certificate trustedCertificate = ...

SSLFactory.builder()
          .withIdentityMaterial(privateKey, privateKeyPassword, certificateChain)
          .withTrustMaterial(trustedCertificate)
          .build();
```

##### Using PEM Files
Support for using pem formatted private key and certificates from classpath, any directory or as an InputStream. See [PemUtilsShould](sslcontext-kickstart-for-pem/src/test/java/nl/altindag/sslcontext/util/PemUtilsShould.java) for detailed usages.
Add the dependency below to use this feature, it also includes the core features from the library such as SSLFactory.
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart-for-pem</artifactId>
</dependency>
```
```text
 * EXAMPLE FILES
 *
 * [some-trusted-certificate.pem]
 * -----BEGIN CERTIFICATE-----
 *             ...
 *             ...
 * -----END CERTIFICATE-----
 *
 * [private-key.pem]
 * -----BEGIN PRIVATE KEY-----
 *             ...
 *             ...
 * -----END PRIVATE KEY-----
 *
 * [private-key.pem]
 * -----BEGIN RSA PRIVATE KEY-----
 *             ...
 *             ...
 * -----END RSA PRIVATE KEY-----
 *
 * [private-key.pem]
 * -----BEGIN ENCRYPTED PRIVATE KEY-----
 *             ...
 *             ...
 * -----END ENCRYPTED PRIVATE KEY-----
 */
```
Example usage:
```
X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial("certificate.pem", "private-key.pem");
X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial("some-trusted-certificate.pem");

SSLFactory.builder()
          .withIdentityMaterial(keyManager)
          .withTrustMaterial(trustManager)
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
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.NettySslContextUtils;
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
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.JettySslContextUtils;
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
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.ApacheSslContextUtils;
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