[![Actions Status](https://github.com/Hakky54/sslcontext-kickstart/workflows/Build/badge.svg)](https://github.com/Hakky54/sslcontext-kickstart/actions)
[![Maintainability](https://api.codeclimate.com/v1/badges/f7b10f052a46a53f83be/maintainability)](https://codeclimate.com/github/Hakky54/sslcontext-kickstart/maintainability)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/4747ca09527040e99f3c2ac212af3424)](https://www.codacy.com/manual/Hakky54/sslcontext-kickstart?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Hakky54/sslcontext-kickstart&amp;utm_campaign=Badge_Grade)
[![codecov](https://codecov.io/gh/Hakky54/sslcontext-kickstart/branch/master/graph/badge.svg)](https://codecov.io/gh/Hakky54/sslcontext-kickstart)
[![Apache2 license](https://img.shields.io/badge/license-Aache2.0-blue.svg)](https://github.com/Hakky54/sslcontext-kickstart/blob/master/LICENSE)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.hakky54/sslcontext-kickstart/badge.svg)](https://mvnrepository.com/artifact/io.github.hakky54/sslcontext-kickstart)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FHakky54%2Fsslcontext-kickstart.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2FHakky54%2Fsslcontext-kickstart?ref=badge_shield)

# Install with [maven](https://mvnrepository.com/artifact/io.github.hakky54/sslcontext-kickstart)
```xml
<dependency>
    <groupId>io.github.hakky54</groupId>
    <artifactId>sslcontext-kickstart</artifactId>
    <version>2.0.0</version>
</dependency>
```

# Introduction
SSLContext Kickstart is a library which provides an easy to use Helper class for configuring a http client to communicate over SSL/TLS for one way authentication or two way authentication.

### Advantages:
- No need for low-level SSLContext configuration anymore
- No knowledge needed about TrustManager, TrustManagerFactory, KeyManager, KeyManagerFactory and how to create it.
- Above classes will all be created with just providing an identity and a trustStore

### Definition
- Identity: A KeyStore which holds the key pair also known as private and public key
- TrustStore: A KeyStore containing one or more certificates also known as public key. This KeyStore contains a list of trusted certificates
- One way authentication: Https connection where the client validates the certificate of the counter party
- Two way authentication: Https connection where the client as well as the counter party validates the certificate, also known as mutual authentication

### Tested HTTP Clients
Below is a list of clients which have already been tested with examples, see in the [ClientConfig class](https://github.com/Hakky54/mutual-tls-ssl/blob/master/client/src/main/java/nl/altindag/client/ClientConfig.java) for detailed configuration
  - Apache HttpClient
  - JDK HttpClient
  - Old JDK HttpClient
  - Spring RestTemplate
  - Spring WebFlux WebClient Netty
  - Spring WebFlux WebClient Jetty
  - OkHttp
  - Jersey Client
  - Old Jersey Client
  - Google HttpClient
  - Unirest
  - Retrofit
  - Finagle
  - Akka Http Client
  
There is a github project available named [Mutual-tls-ssl](https://github.com/Hakky54/mutual-tls-ssl) which provides a tutorial an example setup for four scenarios:
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

import nl.altindag.sslcontext.SSLContextHelper;

public class App {

    public static void main(String[] args) throws IOException {
        SSLContextHelper sslContextHelper = SSLContextHelper.builder()
                                                            .withDefaultJdkTrustStore()
                                                            .build();
        HttpClient httpClient = HttpClients.custom()
                                           .setSSLContext(sslContextHelper.getSslContext())
                                           .setSSLHostnameVerifier(sslContextHelper.getHostnameVerifier())
                                           .build();

        HttpGet request = new HttpGet("https://github.com/");
        HttpResponse response = httpClient.execute(request);
    }

}
```
One way authentication with custom trustStore 
```java
SSLContextHelper.builder()
                .withTrustStore(trustStore, trustStorePassword)
                .build();
```

One way authentication while trusting all certificates without validation, not recommended to use at production!
```java
SSLContextHelper.builder()
                .withTrustingAllCertificatesWithoutValidation()
                .build();
```

One way authentication with specific encryption protocol version and option to validate the hostname within the request against the SAN field of a certificate.
```java
SSLContextHelper.builder()
                .withTrustStore(trustStore, trustStorePassword)
                .withHostnameVerifierEnabled(true)
                .withProtocol("TLSv1.2")
                .build();
```

Two way authentication with custom trustStore, hostname verifier and encryption protocol version
```java
SSLContextHelper.builder()
                .withIdentity(identity, identityPassword)
                .withTrustStore(trustStore, trustStorePassword)
                .withHostnameVerifierEnabled(true)
                .withProtocol("TLSv1.2")
                .build();
```


## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FHakky54%2Fsslcontext-kickstart.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FHakky54%2Fsslcontext-kickstart?ref=badge_large)