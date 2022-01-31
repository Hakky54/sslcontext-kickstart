package nl.altindag.ssl.decryptor;

import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import static nl.altindag.ssl.util.ValidationUtils.requireNotNull;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.PemUtils PemUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 *
 * @author Hakan Altindag
 */
public final class PemDecryptor implements BouncyFunction<char[], PEMDecryptorProvider> {

    private static final PemDecryptor INSTANCE = new PemDecryptor();
    private static final JcePEMDecryptorProviderBuilder PEM_DECRYPTOR_PROVIDER_BUILDER = new JcePEMDecryptorProviderBuilder();

    private PemDecryptor() {}

    @Override
    public PEMDecryptorProvider apply(char[] password) {
        requireNotNull(password, () -> new IllegalArgumentException("A password is mandatory with an encrypted key"));
        return PEM_DECRYPTOR_PROVIDER_BUILDER.build(password);
    }

    public static BouncyFunction<char[], PEMDecryptorProvider> getInstance() {
        return INSTANCE;
    }

}