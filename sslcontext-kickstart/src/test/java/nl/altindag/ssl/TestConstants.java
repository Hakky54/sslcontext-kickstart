package nl.altindag.ssl;

public class TestConstants {

    public static final String IDENTITY_FILE_NAME = "identity.jks";
    public static final String TRUSTSTORE_FILE_NAME = "truststore.jks";

    public static final char[] IDENTITY_PASSWORD = "secret".toCharArray();
    public static final char[] TRUSTSTORE_PASSWORD = "secret".toCharArray();
    public static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";
    public static final String TEMPORALLY_KEYSTORE_LOCATION = System.getProperty("user.home");
    public static final String EMPTY = "";

}
