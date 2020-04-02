[![Actions Status](https://github.com/Hakky54/sslcontext-kickstart/workflows/Build/badge.svg)](https://github.com/Hakky54/sslcontext-kickstart/actions)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=io.github.hakky54%3Asslcontext-kickstart&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Asslcontext-kickstart)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/4747ca09527040e99f3c2ac212af3424)](https://www.codacy.com/manual/Hakky54/sslcontext-kickstart?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Hakky54/sslcontext-kickstart&amp;utm_campaign=Badge_Grade)
[![codecov](https://codecov.io/gh/Hakky54/sslcontext-kickstart/branch/master/graph/badge.svg)](https://codecov.io/gh/Hakky54/sslcontext-kickstart)
[![Apache2 license](https://img.shields.io/badge/license-Aache2.0-blue.svg)](https://github.com/Hakky54/sslcontext-kickstart/blob/master/LICENSE)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.hakky54/sslcontext-kickstart/badge.svg)](https://mvnrepository.com/artifact/io.github.hakky54/sslcontext-kickstart)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FHakky54%2Fsslcontext-kickstart.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2FHakky54%2Fsslcontext-kickstart?ref=badge_shield)

[![SonarCloud](https://sonarcloud.io/images/project_badges/sonarcloud-white.svg)](https://sonarcloud.io/dashboard?id=io.github.hakky54%3Asslcontext-kickstart)

# Install with [maven](https://mvnrepository.com/artifact/io.github.hakky54/sslcontext-kickstart)
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart</artifactId>
    <version>3.0.4</version>
</dependency>
```

# Introduction
SSLContext Kickstart is a library which provides an easy to use [Factory class](#usage) for configuring a http client to communicate over SSL/TLS for one way authentication or two way authentication.

### Acknowledgement
I would like to thank [Cody A. Ray](https://github.com/codyaray) for his contribution to the community regarding loading multiple Keystores into the SSLContext. The limitation of the JDK is to only support one keystore for the KeyManagerFactory and only one keystore for the TrustManagerFactory.
The code snippets which Cody has shared are now available within this library and can be found here: [CompositeX509KeyManager](src/main/java/nl/altindag/sslcontext/keymanager/CompositeX509KeyManager.java) and [CompositeX509TrustManager](src/main/java/nl/altindag/sslcontext/trustmanager/CompositeX509TrustManager.java) 

The original article can be found here: [Codyaray - Java SSL with Multiple KeyStores](http://codyaray.com/2013/04/java-ssl-with-multiple-keystores).

### Advantages:
- No need for low-level SSLContext configuration anymore
- No knowledge needed about SSLContext, TrustManager, TrustManagerFactory, KeyManager, KeyManagerFactory and how to create it.
- Above classes will all be created with just providing an identity and a trustStore

### Definition
  - Identity: A KeyStore which holds the key pair also known as private and public key
  - TrustStore: A KeyStore containing one or more certificates also known as public key. This KeyStore contains a list of trusted certificates
  - One way authentication (also known as one way tls, one way ssl): Https connection where the client validates the certificate of the counter party
  - Two way authentication (also known as two way tls, two way ssl, mutual authentication): Https connection where the client as well as the counter party validates the certificate, also known as mutual authentication

### Tested HTTP Clients
Below is a list of clients which have already been tested with examples, see in the [ClientConfig class](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/ClientConfig.java) and [service directory](https://github.com/Hakky54/mutual-tls-ssl/tree/master/client/src/main/java/nl/altindag/client/service) for detailed configuration
  - [Apache HttpClient](https://github.com/apache/httpcomponents-client)
  - [JDK HttpClient](https://openjdk.java.net/groups/net/httpclient/intro.html)
  - [Old JDK HttpClient](https://docs.oracle.com/javase/tutorial/networking/urls/readingWriting.html)
  - Spring RestTemplate
  - Spring WebFlux WebClient Netty
  - Spring WebFlux WebClient Jetty
  - [OkHttp](https://github.com/square/okhttp)
  - [Jersey Client](https://eclipse-ee4j.github.io/jersey/)
  - Old Jersey Client
  - [Google HttpClient](https://github.com/googleapis/google-http-java-client)
  - [Unirest](https://github.com/Kong/unirest-java)
  - [Retrofit](https://github.com/square/retrofit)
  - [Twitter Finagle Http Client](https://github.com/twitter/finagle)
  - [Akka Http Client](https://github.com/akka/akka-http)
  - [Dispatch Reboot Http Client](https://github.com/dispatch/reboot)
  - [Async Http Client](https://github.com/AsyncHttpClient/async-http-client)
  - [ScalaJ Http Client](https://github.com/scalaj/scalaj-http)  
  
There is a github project available named [Mutual-tls-ssl](https://github.com/Hakky54/mutual-tls-ssl) which provides a tutorial containing steps for setting up these four scenarios:
 - No security
 - One way authentication
 - Two way authentication
 - Two way authentication with trusting the Certificate Authority

It will also explain how to create KeyStores, Certificates, Certificate Signing Requests and how to implement it.

# Usage
Example configuration with apache http client, or see here for other clients: [ClientConfig class](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/ClientConfig.java)
```java
import java.io.IOException;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;

import nl.altindag.sslcontext.SSLFactory;

public class App {

    public static void main(String[] args) throws IOException, JSONException {
        SSLFactory sslFactory = SSLFactory.builder()
                .withDefaultJdkTrustStore()
                .build();

        HttpClient httpClient = HttpClients.custom()
                .setSSLContext(sslFactory.getSslContext())
                .setSSLHostnameVerifier(sslFactory.getHostnameVerifier())
                .build();

        HttpGet request = new HttpGet("https://api.chucknorris.io/jokes/random");

        HttpResponse response = httpClient.execute(request);
        String chuckNorrisJoke = new JSONObject(EntityUtils.toString(response.getEntity())).getString("value");

        System.out.println(String.format("Received the following status code: %d", response.getStatusLine().getStatusCode()));
        System.out.println(String.format("Received the following joke: %s", chuckNorrisJoke));
    }

}
```
Response:
```text
Received the following status code: 200
Received the following joke: If a black cat crosses your path, you have bad luck. If Chuck Norris crosses your path, it was nice knowing you.
```
### Other possible configurations for SSLFactory
One way authentication with custom trustStore 
```text
SSLFactory.builder()
          .withTrustStore(trustStore, trustStorePassword)
          .build();
```

One way authentication while trusting all certificates without validation, not recommended to use at production!
```text
SSLFactory.builder()
          .withTrustingAllCertificatesWithoutValidation()
          .build();
```

One way authentication with specific encryption protocol version and option to validate the hostname within the request against the SAN field of a certificate.
If you are using java 11 or newer, than you are also able to use TLSv1.3 as encryption protocol. Just provide `TLSv1.3` as protocol argument and it will work out-of-the-box.
```text
SSLFactory.builder()
          .withTrustStore(trustStore, trustStorePassword)
          .withHostnameVerifierEnabled(true)
          .withProtocol("TLSv1.2")
          .build();
```

Two way authentication with custom trustStore, hostname verifier and encryption protocol version
```text
SSLFactory.builder()
          .withIdentity(identity, identityPassword)
          .withTrustStore(trustStore, trustStorePassword)
          .withHostnameVerifierEnabled(true)
          .withProtocol("TLSv1.2")
          .build();
```

Support for using multiple identities and trustStores 
```text
SSLFactory.builder()
          .withIdentity(identityA, identityPasswordA)
          .withIdentity(identityB, identityPasswordB)
          .withIdentity(identityC, identityPasswordC)
          .withTrustStore(trustStoreA, trustStorePasswordA)
          .withTrustStore(trustStoreB, trustStorePasswordB)
          .withTrustStore(trustStoreC, trustStorePasswordC)
          .withTrustStore(trustStoreD, trustStorePasswordD)
          .withHostnameVerifierEnabled(true)
          .withProtocol("TLSv1.2")
          .build();
```

## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FHakky54%2Fsslcontext-kickstart.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FHakky54%2Fsslcontext-kickstart?ref=badge_large)
