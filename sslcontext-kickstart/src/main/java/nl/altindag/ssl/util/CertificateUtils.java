package nl.altindag.ssl.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class CertificateUtils {

    private static final String CERTIFICATE_TYPE = "X.509";
    private static final Pattern CERTIFICATE_PATTERN = Pattern.compile("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", Pattern.DOTALL);

    private static final String NEW_LINE = "\n";
    private static final String EMPTY = "";

    private CertificateUtils() {}

    public static String generateAlias(Certificate certificate) {
        if (certificate instanceof X509Certificate) {
            return ((X509Certificate) certificate)
                    .getSubjectX500Principal()
                    .getName();
        } else {
            return UUID.randomUUID().toString();
        }
    }

    public static List<Certificate> loadCertificate(String... certificatePaths) throws CertificateException, IOException {
        return loadCertificate(certificatePath -> CertificateUtils.class.getClassLoader().getResourceAsStream(certificatePath), certificatePaths);
    }

    public static List<Certificate> loadCertificate(Path... certificatePaths) throws CertificateException, IOException {
        return loadCertificate(certificatePath -> {
            try {
                return Files.newInputStream(certificatePath, StandardOpenOption.READ);
            } catch (IOException exception) {
                throw new UncheckedIOException(exception);
            }
        }, certificatePaths);
    }

    public static List<Certificate> loadCertificate(InputStream... certificateStreams) throws CertificateException, IOException {
        return loadCertificate(Function.identity(), certificateStreams);
    }

    @SafeVarargs
    private static <T> List<Certificate> loadCertificate(Function<T, InputStream> resourceMapper, T... resources) throws IOException, CertificateException {
        List<Certificate> certificates = new ArrayList<>();
        for (T resource : resources) {
            try (InputStream certificateStream = resourceMapper.apply(resource)) {
                certificates.addAll(parseCertificate(certificateStream));
            }
        }

        return Collections.unmodifiableList(certificates);
    }

    private static List<Certificate> parseCertificate(InputStream certificateStream) throws IOException, CertificateException {
        String content = IOUtils.getContent(certificateStream);
        return parseCertificate(content);
    }

    public static List<Certificate> parseCertificate(String certificateContent) throws IOException, CertificateException {
        List<Certificate> certificates = new ArrayList<>();
        Matcher certificateMatcher = CERTIFICATE_PATTERN.matcher(certificateContent);

        while (certificateMatcher.find()) {
            String sanitizedCertificate = certificateMatcher.group(1).replace(NEW_LINE, EMPTY).trim();
            byte[] decodedCertificate = Base64.getDecoder().decode(sanitizedCertificate);
            try(ByteArrayInputStream certificateAsInputStream = new ByteArrayInputStream(decodedCertificate)) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
                Certificate certificate = certificateFactory.generateCertificate(certificateAsInputStream);
                certificates.add(certificate);
            }
        }

        return certificates;
    }

}
