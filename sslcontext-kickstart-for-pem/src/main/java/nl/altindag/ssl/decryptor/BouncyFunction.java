package nl.altindag.ssl.decryptor;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;

import java.io.IOException;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.PemUtils PemUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 *
 * @author Hakan Altindag
 */
@FunctionalInterface
public interface BouncyFunction<T, R> {

    BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();
    String NO_PASSWORD_EXCEPTION_MESSAGE = "A password is mandatory with an encrypted key";

    R apply(T t) throws OperatorCreationException, PKCSException, IOException;

    default <V> BouncyFunction<T, V> andThen(BouncyFunction<? super R, ? extends V> after) {
        return (T t) -> after.apply(apply(t));
    }

}
