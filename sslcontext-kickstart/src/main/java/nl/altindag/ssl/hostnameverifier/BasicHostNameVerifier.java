/*
 * Copyright 2019-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.altindag.ssl.hostnameverifier;

import nl.altindag.ssl.exception.GenericHostnameVerifierException;
import nl.altindag.ssl.util.StringUtils;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.net.IDN;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.HostnameVerifierUtils HostnameVerifierUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 * </p>
 *
 * A HostnameVerifier consistent with [RFC 2818][rfc_2818].
 *
 * [rfc_2818]: http://www.ietf.org/rfc/rfc2818.txt
 *
 * This HostnameVerifier is copied from OkHttp library, see here for the original content:
 * - https://github.com/square/okhttp/blob/69ae7f3e10dae0554f3181edaa52bcd77ee448ab/okhttp/src/jvmMain/kotlin/okhttp3/internal/tls/OkHostnameVerifier.kt#L1
 * - https://github.com/square/okhttp/blob/69ae7f3e10dae0554f3181edaa52bcd77ee448ab/okhttp/src/jvmMain/kotlin/okhttp3/internal/-HostnamesJvm.kt#L1
 * - https://github.com/square/okhttp/blob/69ae7f3e10dae0554f3181edaa52bcd77ee448ab/okhttp/src/commonMain/kotlin/okhttp3/internal/-HostnamesCommon.kt#L1
 *
 * @author swankjesse - Jesse Wilson
 * @author yschimke - Yuri Schimke
 * @author Goooler
 * @author jemaystermind - Jeremy Tecson
 * @author JakeWharton - Jake Wharton
 * @author Hakan Altindag
 */
public final class BasicHostNameVerifier implements HostnameVerifier {

    private static final HostnameVerifier INSTANCE = new BasicHostNameVerifier();
    private static final CharsetEncoder ASCII_ENCODER = StandardCharsets.US_ASCII.newEncoder();
    private static final Pattern VERIFY_AS_IP_ADDRESS = Pattern.compile("([0-9a-fA-F]*:[0-9a-fA-F:.]*)|([\\d.]+)");
    private static final int ALT_DNS_NAME = 2;
    private static final int ALT_IPA_NAME = 7;

    private BasicHostNameVerifier() {}

    public static HostnameVerifier getInstance() {
        return INSTANCE;
    }

    @Override
    public boolean verify(String host, SSLSession sslSession) {
        if (!isAscii(host)) {
            return false;
        }

        Optional<X509Certificate> peerCertificate = getPeerCertificate(sslSession);
        return peerCertificate.isPresent() && verify(host, peerCertificate.get());
    }

    /**
     * Returns true if the [String] is ASCII encoded.
     */
    private boolean isAscii(String value) {
        return ASCII_ENCODER.canEncode(value);
    }

    /**
     * Returns the first certificate from the peer certificates if present.
     */
    private Optional<X509Certificate> getPeerCertificate(SSLSession sslSession) {
        try {
            return Arrays.stream(sslSession.getPeerCertificates())
                    .filter(Objects::nonNull)
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .findFirst();
        } catch (SSLPeerUnverifiedException e) {
            return Optional.empty();
        }
    }

    private boolean verify(String host, X509Certificate certificate) {
        if (canParseAsIpAddress(host)) {
            return verifyIpAddress(host, certificate);
        } else {
            return verifyHostname(host, certificate);
        }
    }

    boolean canParseAsIpAddress(String value) {
        return VERIFY_AS_IP_ADDRESS.matcher(value).matches();
    }

    /**
     * Returns true if [certificate] matches [hostname].
     */
    private boolean verifyIpAddress(String ipAddress, X509Certificate certificate) {
        String canonicalIpAddress = toCanonicalHost(ipAddress);
        if (canonicalIpAddress == null) {
            return false;
        }

        List<String> subjectAltNames = getSubjectAltNames(certificate, ALT_IPA_NAME);
        return subjectAltNames.stream().anyMatch(subjectAltName -> canonicalIpAddress.equals(toCanonicalHost(subjectAltName)));
    }

    /**
     * If this is an IP address, this returns the IP address in canonical form.
     * <p>
     * Otherwise this performs IDN ToASCII encoding and canonicalize the result to lowercase. For
     * example this converts `☃.net` to `xn--n3h.net`, and `WwW.GoOgLe.cOm` to `www.google.com`.
     * `null` will be returned if the host cannot be ToASCII encoded or if the result contains
     * unsupported ASCII characters.
     */
    private String toCanonicalHost(String host) {
        String result = host;
        // If the input contains a :, it’s an IPv6 address.
        if (host.contains(":")) {
            // If the input is encased in square braces "[...]", drop 'em.
            if (host.startsWith("[" ) && host.endsWith("]")) {
                result = host.substring(1, host.length() - 1);
            }

            try {
                InetAddress inetAddress = InetAddress.getByName(result);
                return inetAddress.getHostAddress();
            } catch (UnknownHostException e) {
                throw new GenericHostnameVerifierException(e);
            }
        }

        try {
            result = IDN.toASCII(host).toLowerCase(Locale.US);
            if (result.isEmpty()) {
                return null;
            }

            if (containsInvalidHostnameAsciiCodes(result)) {
                // The IDN ToASCII result contains illegal characters.
                return null;
            } else if (containsInvalidLabelLengths(result)) {
                // The IDN ToASCII result contains invalid labels.
                return null;
            } else {
                return result;
            }
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private List<String> getSubjectAltNames(X509Certificate certificate, int type) {
        try {
            Collection<List<?>> subjectAlternativeNames = Optional.ofNullable(certificate.getSubjectAlternativeNames())
                    .orElseGet(Collections::emptyList);

            return subjectAlternativeNames.stream()
                    .filter(Objects::nonNull)
                    .filter(subjectAlternativeName -> !subjectAlternativeName.isEmpty())
                    .filter(subjectAlternativeName -> subjectAlternativeName.size() == 2)
                    .filter(subjectAlternativeName -> subjectAlternativeName.get(0) instanceof Integer && ((Integer) subjectAlternativeName.get(0)) == type)
                    .map(subjectAlternativeName -> subjectAlternativeName.get(1))
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .collect(Collectors.toList());

        } catch (CertificateParsingException exception) {
            return Collections.emptyList();
        }
    }

    private boolean containsInvalidHostnameAsciiCodes(String hostname) {
        for (int i = 0; i < hostname.length(); i++) {
            char c = hostname.charAt(i);

            // The WHATWG Host parsing rules accepts some character codes which are invalid by
            // definition for OkHttp's host header checks (and the WHATWG Host syntax definition). Here
            // we rule out characters that would cause problems in host headers.
            if (c <= '\u001f' || c >= '\u007f') {
                return true;
            }

            // Check for the characters mentioned in the WHATWG Host parsing spec:
            // U+0000, U+0009, U+000A, U+000D, U+0020, "#", "%", "/", ":", "?", "@", "[", "\", and "]"
            // (excluding the characters covered above).
            if (" #%/:?@[\\]".indexOf(c) != -1) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns true if the length is not valid for DNS (empty or greater than 253 characters), or if any
     * label is longer than 63 characters. Trailing dots are okay.
     */
    private boolean containsInvalidLabelLengths(String hostname) {
        if (hostname.length() < 1 || hostname.length() > 253) {
            return true;
        }

        int labelStart = 0;
        while (true) {
            int dot = hostname.indexOf('.', labelStart);
            int labelLength;
            if (dot == -1) {
                labelLength = hostname.length() - labelStart;
            } else {
                labelLength = dot - labelStart;
            }
            if (labelLength < 1 || labelLength > 63) {
                return true;
            }
            if (dot == -1) {
                break;
            }
            if (dot == hostname.length() - 1) {
                break; // Trailing '.' is allowed.
            }
            labelStart = dot + 1;
        }

        return false;
    }

    private boolean verifyHostname(String hostname, X509Certificate certificate) {
        List<String> subjectAltNames = getSubjectAltNames(certificate, ALT_DNS_NAME);
        return subjectAltNames.stream().anyMatch(subjectAltName -> verifyHostname(hostname, subjectAltName));
    }

    /**
     * Returns true if [hostname] matches the domain name pattern.
     *
     * @param hostname lower-case host name.
     * @param domainNamePattern domain name pattern from certificate. Maybe a wildcard pattern such as
     *     `*.android.com`.
     */
    private boolean verifyHostname(String hostname, String domainNamePattern) {
        if (isHostnameInValid(hostname) || isHostnameInValid(domainNamePattern)) {
            return false;
        }

        String resultingHostname = toAbsolute(hostname);
        String resultingDomainNamePattern = toAbsolute(domainNamePattern);
        // Hostname and pattern are now absolute domain names.

        resultingHostname = asciiToLowercase(resultingHostname);
        resultingDomainNamePattern = asciiToLowercase(resultingDomainNamePattern);
        // Hostname and pattern are now in lower case -- domain names are case-insensitive.

        if (!resultingDomainNamePattern.contains("*")) {
            // Not a wildcard pattern -- hostname and pattern must match exactly.
            return resultingHostname.equals(resultingDomainNamePattern);
        }

        // Wildcard pattern
        return verifyWildcardPattern(resultingHostname, resultingDomainNamePattern);
    }

    private boolean isHostnameInValid(String hostname) {
        return StringUtils.isBlank(hostname) || hostname.startsWith(".") || hostname.endsWith("..");
    }

    /**
     * Normalize hostname by turning it into absolute domain names if it is not
     * yet absolute. This is needed because server certificates do not normally contain absolute
     * names, but they should be treated as absolute. At the same time, any hostname
     * presented to this method should also be treated as absolute for the purposes of matching
     * to the server certificate.
     *   www.android.com  matches www.android.com
     *   www.android.com  matches www.android.com.
     *   www.android.com. matches www.android.com.
     *   www.android.com. matches www.android.com
     */
    private String toAbsolute(String hostname) {
        String absoluteHostname = hostname;
        if (!absoluteHostname.startsWith(".")) {
            absoluteHostname += ".";
        }
        return absoluteHostname;
    }

    /**
     * This is like [toLowerCase] except that it does nothing if this contains any non-ASCII
     * characters. We want to avoid lower casing special chars like U+212A (Kelvin symbol) because
     * they can return ASCII characters that match real hostnames.
     */
    private String asciiToLowercase(String value) {
        return isAscii(value) ? value.toLowerCase(Locale.US) : value;
    }

    /**
     * WILDCARD PATTERN RULES:
     * 1. Asterisk (*) is only permitted in the left-most domain name label and must be the
     *    only character in that label (i.e., must match the whole left-most label).
     *    For example, *.example.com is permitted, while *a.example.com, a*.example.com,
     *    a*b.example.com, a.*.example.com are not permitted.
     * 2. Asterisk (*) cannot match across domain name labels.
     *    For example, *.example.com matches test.example.com but does not match
     *    sub.test.example.com.
     * 3. Wildcard patterns for single-label domain names are not permitted.
     */
//    @SuppressWarnings("RedundantIfStatement")
    private boolean verifyWildcardPattern(String hostname, String domainNamePattern) {
        if (!domainNamePattern.startsWith("*.") || domainNamePattern.indexOf("*", 1) != -1) {
            // Asterisk (*) is only permitted in the left-most domain name label and must be the only
            // character in that label
            return false;
        }

        // Optimization: check whether hostname is too short to match the pattern. hostName must be at
        // least as long as the pattern because asterisk must match the whole left-most label and
        // hostname starts with a non-empty label. Thus, asterisk has to match one or more characters.
        if (hostname.length() < domainNamePattern.length()) {
            return false; // Hostname too short to match the pattern.
        }

        if ("*.".equals(domainNamePattern)) {
            return false; // Wildcard pattern for single-label domain name -- not permitted.
        }

        // Hostname must end with the region of pattern following the asterisk.
        String suffix = domainNamePattern.substring(1);
        if (!hostname.endsWith(suffix)) {
            return false; // Hostname does not end with the suffix.
        }

        // Check that asterisk did not match across domain name labels.
        int suffixStartIndexInHostname = hostname.length() - domainNamePattern.length();
        if (suffixStartIndexInHostname > 0 && hostname.lastIndexOf(".", suffixStartIndexInHostname - 1) != -1) {
            return false; // Asterisk is matching across domain name labels -- not permitted.
        }

        // Hostname matches pattern.
        return true;
    }

}
