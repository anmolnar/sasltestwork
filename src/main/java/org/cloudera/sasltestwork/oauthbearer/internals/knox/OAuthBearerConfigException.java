package org.cloudera.sasltestwork.oauthbearer.internals.knox;

public class OAuthBearerConfigException extends RuntimeException {
  private static final long serialVersionUID = -8056105648062343518L;

  public OAuthBearerConfigException(String s) {
    super(s);
  }

  public OAuthBearerConfigException(String message, Throwable cause) {
    super(message, cause);
  }

}
