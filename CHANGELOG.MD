<h2 class="github">Changelog</h2>

This list is not intended to be all-encompassing - it will document major and breaking API 
changes with their rationale when appropriate:

### v5.4.0
- Ability to wrap old X509KeyManager into X509ExtendedKeyManager
- Ability to wrap old X509TrustManager into X509ExtendedTrustManager
- Added CertificateUtils
- Support for custom Security Provider and SSLContext protocol
- Marked ApacheSslContextUtils#toLayeredConnectionSocketFactory deprecated