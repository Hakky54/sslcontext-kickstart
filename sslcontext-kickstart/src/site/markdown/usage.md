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

##### Loading keystore and trust store from InputStream
```text
InputStream keyStoreStream = ...
InputStream trustStoreStream = ...

SSLFactory.builder()
          .withIdentityMaterial(keyStoreStream, "password".toCharArray())
          .withTrustMaterial(trustStoreStream, "password".toCharArray())
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

##### Support for swapping KeyManager and TrustManager at runtime
It is possible to swap a KeyManager and TrustManager from a SSLContext, SSLSocketFactory and SSLServerSocketFactory while already using it within your client or server at runtime. This option will enable to refresh the identity and trust material of a server or client without the need of restarting your application or recreating it with SSLFactory. The identity and trust material may expire at some point in time and needs to be replaced to be still functional.
Restart of the application with a traditional setup is unavoidable and can result into a downtime for x amount of time. A restart is not needed when using the setup below.
```text
SSLFactory sslFactory = SSLFactory.builder()
          .withSwappableIdentityMaterial()
          .withIdentityMaterial("identity.jks", "password".toCharArray())
          .withSwappableTrustMaterial()
          .withTrustMaterial("truststore.jks", "password".toCharArray())
          .build();
          
HttpClient httpClient = HttpClient.newBuilder()
          .sslParameters(sslFactory.getSslParameters())
          .sslContext(sslFactory.getSslContext())
          .build()

// execute https request
HttpResponse<String> response = httpClient.send(aRequest, HttpResponse.BodyHandlers.ofString());

// swap identity and trust materials and reuse existing http client
KeyManagerUtils.swapKeyManager(sslFactory.getKeyManager().get(), anotherKeyManager);
TrustManagerUtils.swapTrustManager(sslFactory.getTrustManager().get(), anotherTrustManager);
HttpResponse<String> response = httpClient.send(aRequest, HttpResponse.BodyHandlers.ofString());
```
See here for a basic reference implementation for a server: [GitHub - Instant SSL Reloading](https://github.com/Hakky54/instant-ssl-reloading)

##### Support for using a single KeyStore which contains multiple keys with different passwords
```text
KeyStore keyStore = ...
X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(keyStore, Map.of(
        "foo","foo-password".toCharArray(),
        "bar","bar-password".toCharArray(),
        "lorum-ipsum","lorum-ipsum-password".toCharArray()
));

SSLFactory.builder()
          .withIdentityMaterial(keyManager)
          .withDefaultTrustMaterial()
          .build();
```
##### Routing identity material to specific host
It may occur that the client is sending the wrong certificate to the server when using multiple identities. This will happen when the client certificate has insufficient information for the underlying ssl engine (the KeyManager) and therefore it cannot select the right certificate.
Recreating the certificates can resolve this issue. However, if that is not possible you can provide an option to the engine to use a specific certificate for a given server. Below is an example setup for correctly routing the client identity based on the alias which can be found within the KeyStore file.
```text
SSLFactory.builder()
          .withIdentityMaterial("identity-1.jks", password)
          .withIdentityMaterial("identity-2.jks", password)
          .withTrustMaterial("truststore.jks", password)
          .withClientIdentityRoute("client-alias-one", "https://localhost:8443/", "https://localhost:8453/")
          .withClientIdentityRoute("client-alias-two", "https://localhost:8463/", "https://localhost:8473/")
          .build();
```
##### Updating client identity routes at runtime
```text
SSLFactory sslFactory = SSLFactory.builder()
          .withIdentityMaterial("identity-1.jks", password)
          .withIdentityMaterial("identity-2.jks", password)
          .withTrustMaterial("truststore.jks", password)
          .withClientIdentityRoute("client-alias-one", "https://localhost:8443/", "https://localhost:8453/")
          .withClientIdentityRoute("client-alias-two", "https://localhost:8463/", "https://localhost:8473/")
          .build();

X509ExtendedKeyManager keyManager = sslFactory.getKeyManager().get()

// Add additional routes next to the existing ones
KeyManagerUtils.addClientIdentityRoute(keyManager, "client-alias-one", "https://localhost:8463/", "https://localhost:8473/")

// Override existing routes
KeyManagerUtils.overrideClientIdentityRoute(keyManager, "client-alias-two", "https://localhost:9463/", "https://localhost:9473/")
```
##### Managing ssl session
```text
SSLFactory sslFactory = SSLFactory.builder()
          .withIdentityMaterial("identity.jks", "password".toCharArray())
          .withTrustMaterial("truststore.jks", "password".toCharArray())
          .withSessionTimeout(3600) // Amount of seconds until it will be invalidated
          .withSessionCacheSize(1024) // Amount of bytes until it will be invalidated
          .build();
          
SSLContext sslContext = sslFactory.getSslContext();
          
// Caches can be invalidated with the snippet below
SSLSessionUtils.invalidateCaches(sslContext);

// or any other option:
SSLSessionUtils.invalidateCachesBefore(
        sslContext,
        ZonedDateTime.of(LocalDateTime.of(2021, JANUARY, 1, 15, 55), ZoneOffset.UTC)
);

SSLSessionUtils.invalidateCachesAfter(
        sslContext,
        ZonedDateTime.of(LocalDateTime.of(2021, FEBRUARY, 10, 8, 14), ZoneOffset.UTC)
);

SSLSessionUtils.invalidateCachesBetween(
        sslContext,
        ZonedDateTime.now().minusHours(2),    // from
        ZonedDateTime.now()                   // up till
);
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

#### Using PEM Files
Support for using pem formatted private key and certificates from classpath, any directory or as an InputStream. See [PemUtilsShould](sslcontext-kickstart-for-pem/src/test/java/nl/altindag/ssl/util/PemUtilsShould.java) for detailed usages.
Add the dependency below to use this feature, it also includes the core features from the library such as SSLFactory.
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart-for-pem</artifactId>
</dependency>
```
##### Loading pem files from the classpath
```
X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial("certificate.pem", "private-key.pem");
X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial("some-trusted-certificate.pem");

SSLFactory.builder()
          .withIdentityMaterial(keyManager)
          .withTrustMaterial(trustManager)
          .build();
```
##### Loading pem files from anywhere on the filesystem
```
X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(Paths.get("/path/to/your/certificate.pem"), Paths.get("/path/to/your/"private-key.pem"));
X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(Paths.get("/path/to/your/"some-trusted-certificate.pem"));
```
##### Loading pem files from InputStream
```
InputStream privateKey = ...
InputStream certificate = ...
InputStream trustedCertificates = ...

X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial(certificate, privateKey);
X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(trustedCertificates);
```
##### Loading pem files from string content
```
String privateKey =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
        "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIy3Fposf+2ccCAggA\n" +
        "-----END ENCRYPTED PRIVATE KEY-----\n";

String certificate =
        "-----BEGIN CERTIFICATE-----\n" +
        "g0Y2YBH5v0xmi8sYU7weOcwynkjZARpUltBUQ0pWCF5uJsEB8uE8PPDD3c4=\n" +
        "-----END CERTIFICATE-----\n";

String trustedCertificates =
        "-----BEGIN CERTIFICATE-----\n" +
        "CC01zojqS10nGowxzOiqyB4m6wytmzf0QwjpMw==\n" +
        "-----END CERTIFICATE-----\n";

X509ExtendedKeyManager keyManager = PemUtils.parseIdentityMaterial(certificate, privateKey, "secret".toCharArray());
X509ExtendedTrustManager trustManager = PemUtils.parseTrustMaterial(trustedCertificates);
```
##### Loading encrypted pem files
```
X509ExtendedKeyManager keyManager = PemUtils.loadIdentityMaterial("certificate.pem", "private-key.pem", "secret".toCharArray());
```

##### Migrating from classic configuration
Below is an example of the classic configuration for enabling ssl for your application.
```
-Djavax.net.ssl.trustStore=/path/to/truststore.jks
-Djavax.net.ssl.trustStoreType=jks
-Djavax.net.ssl.trustStorePassword=changeit
-Djavax.net.ssl.keyStore=/path/to/keystore.jks
-Djavax.net.ssl.keyStoreType=jks
-Djavax.net.ssl.keyStorePassword=changeit
-Djdk.tls.client.protocols=TLSv1.3
-Dhttps.protocols=TLSv1.3
```

This can be refactored to the configuration below:
```
SSLFactory sslFactory = SSLFactory.builder()
        .withIdentityMaterial(Paths.get("/path/to/keystore.jks"), "changeit".toCharArray(), "jks")
        .withTrustMaterial(Paths.get("/path/to/truststore.jks"), "changeit".toCharArray(), "jks")
        .withProtocols("TLSv1.3")
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
import nl.altindag.ssl.util.NettySslUtils;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLException;

public class App {
    
    public static void main(String[] args) throws SSLException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build();

        SslContext sslContext = NettySslUtils.forClient(sslFactory).build();
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
import nl.altindag.ssl.util.JettySslUtils;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.http.client.reactive.JettyClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build();
        
        SslContextFactory.Client sslContextFactory = JettySslUtils.forClient(sslFactory);
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
    <artifactId>sslcontext-kickstart-for-apache4</artifactId>
</dependency>
```
```java
import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.util.Apache4SslUtils;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;

public class App {

    public static void main(String[] args) {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultTrustMaterial()
                .build();

        LayeredConnectionSocketFactory socketFactory = Apache4SslUtils.toSocketFactory(sslFactory);

        HttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(socketFactory)
                .build();
    }

}
```