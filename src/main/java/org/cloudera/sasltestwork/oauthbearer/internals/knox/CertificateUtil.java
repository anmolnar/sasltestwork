package org.cloudera.sasltestwork.oauthbearer.internals.knox;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

public class CertificateUtil {
  private static final String PEM_HEADER = "-----BEGIN CERTIFICATE-----\n";
  private static final String PEM_FOOTER = "\n-----END CERTIFICATE-----";

  /**
   * Gets an RSAPublicKey from the provided PEM encoding.
   *
   * @param pem
   *          - the pem encoding from config without the header and footer
   * @return RSAPublicKey the RSA public key
   * @throws CertificateException thrown if a processing error occurred
   */
  public static RSAPublicKey parseRSAPublicKey(String pem) throws CertificateException {
    String fullPem = PEM_HEADER + pem + PEM_FOOTER;
    PublicKey key = null;
    CertificateFactory fact = CertificateFactory.getInstance("X.509");
    ByteArrayInputStream is = new ByteArrayInputStream(
        fullPem.getBytes(StandardCharsets.UTF_8));

    X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
    key = cer.getPublicKey();
    return (RSAPublicKey) key;
  }
}
