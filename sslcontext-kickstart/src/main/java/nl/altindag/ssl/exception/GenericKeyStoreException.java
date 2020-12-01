package nl.altindag.ssl.exception;

public final class GenericKeyStoreException extends GenericSecurityException {

    public GenericKeyStoreException(String message) {
        super(message);
    }

    public GenericKeyStoreException(Throwable cause) {
        super(cause);
    }

    public GenericKeyStoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
