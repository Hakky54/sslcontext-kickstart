package nl.altindag.sslcontext.exception;

public class GenericSecurityException extends RuntimeException {

    public GenericSecurityException(String message) {
        super(message);
    }

    public GenericSecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public GenericSecurityException(Throwable cause) {
        super(cause);
    }

}
