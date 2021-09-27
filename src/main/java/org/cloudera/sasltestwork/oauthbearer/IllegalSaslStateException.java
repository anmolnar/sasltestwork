package org.cloudera.sasltestwork.oauthbearer;

import javax.security.sasl.SaslException;

/**
 * This exception indicates unexpected requests prior to SASL authentication.
 * This could be due to misconfigured security, e.g. if PLAINTEXT protocol
 * is used to connect to a SASL endpoint.
 */
public class IllegalSaslStateException extends SaslException {

  private static final long serialVersionUID = 1L;

  public IllegalSaslStateException(String message) {
    super(message);
  }

  public IllegalSaslStateException(String message, Throwable cause) {
    super(message, cause);
  }

}
