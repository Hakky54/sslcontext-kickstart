package nl.altindag.ssl.decryptor;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;

import static nl.altindag.ssl.util.ValidationUtils.requireNotNull;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.PemUtils PemUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 *
 * @author Hakan Altindag
 */
public final class Pkcs8Decryptor implements BouncyFunction<char[], InputDecryptorProvider> {

    private static final Pkcs8Decryptor INSTANCE = new Pkcs8Decryptor();
    private static final JceOpenSSLPKCS8DecryptorProviderBuilder PKCS8_DECRYPTOR_PROVIDER_BUILDER = new JceOpenSSLPKCS8DecryptorProviderBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME);

    private Pkcs8Decryptor() {}

    @Override
    public InputDecryptorProvider apply(char[] password) throws OperatorCreationException {
        requireNotNull(password, () -> new IllegalArgumentException("A password is mandatory with an encrypted key"));
        return PKCS8_DECRYPTOR_PROVIDER_BUILDER.build(password);
    }

    public static BouncyFunction<char[], InputDecryptorProvider> getInstance() {
        return INSTANCE;
    }

}
