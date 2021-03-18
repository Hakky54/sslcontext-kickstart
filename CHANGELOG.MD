<h2 class="github">Changelog</h2>

This list is not intended to be all-encompassing - it will document major and breaking API 
changes with their rationale when appropriate:

### v6.5.0
- Removed deprecated class and methods for SocketUtils
- Added null check for ssl sessions
- Fixed javadoc warnings
- Added close statements for streams within PemUtils
### v6.4.0
- Update client identity routes at runtime
- Performance improvements such as Lazy creation of some SSL materials
- Added SSLSessionUtils
- Marked SocketUtils as deprecated, alternative is SSLSocketUtils
### v6.3.0
- Added a toggle to hot swap identity material within the SSLFactory
- Added a toggle to hot swap trust material within the SSLFactory
- Added an option to route multiple client identities
### v6.2.0
- Added option to hot swap identity material at runtime
- Added option to hot swap trust material at runtime
- Added option to supply preconfigured ssl engine
- Added support for requiring client authentication from server side
- Removed deprecated method
### v6.1.1
- Switched to system line separator
- Simplified TrustManager
- Removed redundant wrapping of KeyManager and TrustManager
- Renamed sslContextProtocol to sslContextAlgorithm
- Marked sslContextProtocol method as deprecated
- Fixed typos
- Support for loading certificate with "-----BEGIN TRUSTED CERTIFICATE-----" header

### v6.1.0
- Added license header
- Added author
- Added option to create TrustManagerFactory from SSLFactory and TrustManagerUtils
- Added option to create KeyManagerFactory from SSLFactory and KeyManagerUtils
- Made SSLFactory less strict by supporting X509KeyManager and X509TrustManager
- Added option to supply identity as a InputStream for the SSLFactory Builder
- Added option to supply trustStore as a InputStream for the SSLFactory Builder
- Moved KeyManagerBuilder to KeyManagerUtils
- Moved TrustManagerBuilder to TrustManagerUtils
- Added SocketUtils
- Added SSLContextUtils
- Simplified SSLFactory
- Wrapped checked exceptions with unchecked exceptions

### v6.0.0
- Renamed package from nl.altindag.sslcontext to nl.altindag.ssl
- Added UnsafeTrustManager into the TrustManagerUtils
- Removed deprecated methods
- Renamed ApacheSslContextUtils to Apache4SslUtils
- Added Apache5SslUtils
- Renamed NettySslContextUtils to NettySslUtils
- Renamed JettySslContextUtils to JettySslUtils
- Added option to create X509ExtendedKeyManager from PEM as String 
- Added option to create X509ExtendedTrustManager from PEM as String 

### v5.4.0
- Ability to wrap old X509KeyManager into X509ExtendedKeyManager
- Ability to wrap old X509TrustManager into X509ExtendedTrustManager
- Added CertificateUtils
- Support for custom Security Provider and SSLContext protocol
- Marked ApacheSslContextUtils#toLayeredConnectionSocketFactory deprecated

### v5.3.0
- Added wrapped class for SSLServerSocketFactory and SSLSocketFactory
- Enriched SSLFactory with SSLServerSocketFactory and SSLSocketFactory

### v5.2.4
- Disabled lazy initialization of list of protocols and ciphers

### v5.2.3
- Support for custom list of ciphers and protocols

### v5.2.2
- Improved the algorithm for parsing PEM formatted private key

### v5.2.1
- Added support for parsing different types of PEM formatted private keys

### v5.2.0
- Support for loading PEM formatted ssl materials for SSLFactory
- With support for private key, certificate chain and trusted certificates

### v5.1.0
- Support for loading Windows and Mac OS X trusted certificates

### v5.0.1
- Added option to build SSLFactory with KeyStore for trust material without supplying password

### v5.0.0
- Construct SSLFactory with either key material or trust material
- Marked TrustManager as Optional

### v4.1.0
- Removed default SecureRandom object
- Disabled password validation

### v4.0.0
- Removed deprecated methods withTrustStore and withIdentity

### v3.1.2
- Marked withDefaultJdkTrustStore as deprecated

### v3.1.1
- Renamed method withTrustStore to withTrustMaterial
- Renamed method withIdentity to withIdentityMaterial
- Marked withTrustStore and withIdentity as deprecated
- Removed commons-lang3 lib of Apache

### v3.1.0
- Disabled password caching by default and added option to enable it
- Added option to initialize KeyMaterial with custom KeyStore password and Key password

### v3.0.9
- Limited the support of creating CompositeX509ExtendedKeyManager only with X509ExtendedKeyManager
- Limited the support of creating CompositeX509ExtendedTrustManager only with X509ExtendedTrustManager
- Removed support for less secure X509KeyManager and X509TrustManager

### v3.0.8
- Removed isSecurityEnabled function
- Removed isOneWayAuthenticationEnabled function
- Removed isTwoWayAuthenticationEnabled function
- Marked KeyManager as Optional

### v3.0.7
- Added Apache license
- Removed CompositeX509TrustManager
- Added CompositeX509ExtendedTrustManager
- Added CompositeX509ExtendedKeyManager

### v3.0.6
- Removed not required libraries from core library
- Created mapper as separate project for Netty
- Created mapper as separate project for Jetty

### v3.0.5
- Added JettySslContextUtils

### v3.0.4
- Added NettySslContextUtils
- Renamed KeyStoreUtils
- Added Netty mapper into the SSLFactory

### v3.0.3
- Improved exception handler of CompositeX509TrustManager

### v3.0.2
- Updated license and copyright

### v3.0.1
- Added logger into CompositeX509TrustManager
- Marked KeyManagerUtils as final
- Renamed getTrustedCertificate to getTrustedCertificates

### v3.0.0
- Improved exception handling
- Added support for using multiple key materials
- Added logger into UnsafeTrustManager
- Added KeyManagerUtils
- Renamed SSLContextHelper to SSLFactory

### v2.0.0
- Changed data type of passwords from String to char array

### v1.0.3
- Added license

### v1.0.2
- Made trust material optional for SSLFactory

### v1.0.1
- Added jar type within the pom

### v1.0.0
- Initial release