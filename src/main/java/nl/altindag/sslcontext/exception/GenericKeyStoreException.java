package nl.altindag.sslcontext.exception;

public class GenericKeyStoreException extends GenericSecurityException {

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
