package nl.altindag.ssl.keymanager;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.URI;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.Optional;
import java.util.Set;

/**
 * @author Hakan Altindag
 */
interface RoutableX509ExtendedKeyManager extends CombinableX509ExtendedKeyManager {

    Predicate<String> NON_NULL = Objects::nonNull;

    Map<String, List<URI>> getIdentityRoute();

    default <T> String chooseClientAlias(T object,
                                          Predicate<T> predicate,
                                          Function<T, SimpleImmutableEntry<String, Integer>> hostToPortExtractor,
                                          Function<X509ExtendedKeyManager, String> aliasExtractor) {

        Optional<String> preferredClientAlias = getPreferredClientAlias(object, predicate, hostToPortExtractor);
        if (preferredClientAlias.isPresent()) {
            return extractInnerField(aliasExtractor, NON_NULL.and(alias -> preferredClientAlias.get().equals(alias)));
        } else {
            return extractInnerField(aliasExtractor, NON_NULL);
        }
    }

    default <T> Optional<String> getPreferredClientAlias(T object, Predicate<T> predicate, Function<T, SimpleImmutableEntry<String, Integer>> hostToPortExtractor) {
        if (getIdentityRoute().isEmpty()) {
            return Optional.empty();
        }

        if (predicate.test(object)) {
            SimpleImmutableEntry<String, Integer> hostToPort = hostToPortExtractor.apply(object);
            return getPreferredClientAlias(hostToPort.getKey(), hostToPort.getValue());
        }

        return Optional.empty();
    }

    default Optional<String> getPreferredClientAlias(String peerHost, int peerPort) {
        return getIdentityRoute().entrySet().stream()
                .filter(entry -> entry.getValue().stream().anyMatch(uri -> uri.getHost().contains(peerHost)))
                .filter(entry -> entry.getValue().stream().anyMatch(uri -> uri.getPort() == peerPort))
                .findFirst()
                .map(Map.Entry::getKey);
    }

    default <T> String chooseServerAlias(T object,
                                         Predicate<T> predicate,
                                         Function<T, SSLSession> sslSessionExtractor,
                                         Function<X509ExtendedKeyManager, String> aliasExtractor) {

        Optional<String> preferredServerAlias = getPreferredServerAlias(object, predicate, sslSessionExtractor);
        if (preferredServerAlias.isPresent()) {
            return extractInnerField(aliasExtractor, NON_NULL.and(alias -> preferredServerAlias.get().equals(alias)));
        } else {
            return extractInnerField(aliasExtractor, NON_NULL);
        }
    }

    default <T> Optional<String> getPreferredServerAlias(T object, Predicate<T> predicate, Function<T, SSLSession> sslSessionExtractor) {
        if (getIdentityRoute().isEmpty()) {
            return Optional.empty();
        }

        if (predicate.test(object)) {
            SSLSession sslSession = sslSessionExtractor.apply(object);
            if (sslSession instanceof ExtendedSSLSession) {
                List<SNIServerName> requestedServerNames = ((ExtendedSSLSession) sslSession).getRequestedServerNames();
                Set<String> hostnames = requestedServerNames.stream()
                        .map(sniServerName -> new String(sniServerName.getEncoded()))
                        .collect(Collectors.toSet());

                return getPreferredServerAlias(hostnames);
            }
        }

        return Optional.empty();
    }

    default Optional<String> getPreferredServerAlias(Set<String> hostnames) {
        return getIdentityRoute().entrySet().stream()
                .filter(entry -> entry.getValue().stream().anyMatch(uri -> hostnames.stream().anyMatch(hostname -> uri.getHost().contains(hostname))))
                .findFirst()
                .map(Map.Entry::getKey);
    }

}
