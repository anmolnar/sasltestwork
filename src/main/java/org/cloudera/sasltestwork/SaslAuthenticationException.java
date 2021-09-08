package org.cloudera.sasltestwork;

public class SaslAuthenticationException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  public SaslAuthenticationException(String message) {
    super(message);
  }

  public SaslAuthenticationException(String message, Throwable cause) {
    super(message, cause);
  }
}
