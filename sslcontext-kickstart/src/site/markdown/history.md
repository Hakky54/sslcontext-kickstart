### History
As a Java developer I worked for different kinds of clients. Most of the time the application required to call other microservices within the organization or some other http servers.
These requests needed to be secured and therefore it was required to load the ssl materials into the http client. Each client may require different input value to enable https requests and therefore I couldn't just copy-paste my earlier configuration into the new project.
The resulting configuration was in my opinion always verbose, not reusable, hard to test and hard to maintain.

As a developer you also need to know how to properly load your file into your application and consume it as a KeyStore instance. Therefore, you also need to understand how to properly create for example a KeyManager and a TrustManager for you SSLContext.
An alternative for the traditional creation of SSLContext can be simplified if you use a Http Client which relies on libraries of Jetty, Netty or Apache. If you use other clients than you are out of luck.
The sslcontext-kickstart library is taking the responsibility of creating an instance of SSLContext from the provided arguments, and it will provide you all the ssl materials which are required to configure [40+ different Http Client](#tested-http-clients) for Java, Scala and Kotlin.
I wanted the library to be as easy as possible to use for all developers to give them a kickstart when configuring their Http Client. So feel free to provide feedback or feature requests.
The library also provides other utilities such as:

* [CertificateUtils](https://github.com/Hakky54/sslcontext-kickstart/blob/master/sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/CertificateUtils.java)
* [KeyStoreUtils](https://github.com/Hakky54/sslcontext-kickstart/blob/master/sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/KeyStoreUtils.java)
* [KeyManagerUtils](https://github.com/Hakky54/sslcontext-kickstart/blob/master/sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/KeyManagerUtils.java)
* [TrustManagerUtils](https://github.com/Hakky54/sslcontext-kickstart/blob/master/sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/TrustManagerUtils.java)
* [PemUtils](https://github.com/Hakky54/sslcontext-kickstart/blob/master/sslcontext-kickstart-for-pem/src/main/java/nl/altindag/ssl/util/PemUtils.java)
* [SSLSessionUtils](https://github.com/Hakky54/sslcontext-kickstart/blob/master/sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/SSLSessionUtils.java)
* [SSLSocketUtils](https://github.com/Hakky54/sslcontext-kickstart/blob/master/sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/SSLSocketUtils.java)
* [SSLContextUtils](https://github.com/Hakky54/sslcontext-kickstart/blob/master/sslcontext-kickstart/src/main/java/nl/altindag/ssl/util/SSLContextUtils.java)

See the [javadoc](https://sslcontext-kickstart.com/apidocs/index.html) for all the options.
