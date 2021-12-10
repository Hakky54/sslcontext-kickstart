package nl.altindag.ssl.keymanager;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * @author Hakan Altindag
 */
interface CombinableX509ExtendedKeyManager extends X509KeyManager {

    List<X509ExtendedKeyManager> getKeyManagers();

    default <T> T extractInnerField(Function<X509ExtendedKeyManager, T> keyManagerMapper, Predicate<T> predicate) {
        return getKeyManagers().stream()
                .map(keyManagerMapper)
                .filter(predicate)
                .findFirst()
                .orElse(null);
    }

    default String[] getAliases(Function<X509ExtendedKeyManager, String[]> aliasExtractor) {
        return getKeyManagers().stream()
                .map(aliasExtractor)
                .filter(Objects::nonNull)
                .flatMap(Arrays::stream)
                .collect(Collectors.collectingAndThen(Collectors.toList(), this::emptyToNull));
    }

    default String[] emptyToNull(List<String> list) {
        return list.isEmpty() ? null : list.toArray(new String[]{});
    }

}
