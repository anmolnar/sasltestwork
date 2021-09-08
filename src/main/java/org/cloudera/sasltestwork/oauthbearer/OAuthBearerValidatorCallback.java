package org.cloudera.sasltestwork.oauthbearer;

import java.util.Objects;

import javax.security.auth.callback.Callback;

public class OAuthBearerValidatorCallback implements Callback {
  private final String tokenValue;
  private OAuthBearerToken token = null;
  private String errorStatus = null;
  private String errorScope = null;
  private String errorOpenIDConfiguration = null;

  /**
   * Constructor
   *
   * @param tokenValue
   *            the mandatory/non-blank token value
   */
  public OAuthBearerValidatorCallback(String tokenValue) {
    if (Objects.requireNonNull(tokenValue).isEmpty())
      throw new IllegalArgumentException("token value must not be empty");
    this.tokenValue = tokenValue;
  }

  /**
   * Return the (always non-null) token value
   *
   * @return the (always non-null) token value
   */
  public String tokenValue() {
    return tokenValue;
  }

  /**
   * Return the (potentially null) token
   *
   * @return the (potentially null) token
   */
  public OAuthBearerToken token() {
    return token;
  }

  /**
   * Return the (potentially null) error status value as per
   * <a href="https://tools.ietf.org/html/rfc7628#section-3.2.2">RFC 7628: A Set
   * of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth</a>
   * and the <a href=
   * "https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#extensions-error">IANA
   * OAuth Extensions Error Registry</a>.
   *
   * @return the (potentially null) error status value
   */
  public String errorStatus() {
    return errorStatus;
  }

  /**
   * Return the (potentially null) error scope value as per
   * <a href="https://tools.ietf.org/html/rfc7628#section-3.2.2">RFC 7628: A Set
   * of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth</a>.
   *
   * @return the (potentially null) error scope value
   */
  public String errorScope() {
    return errorScope;
  }

  /**
   * Return the (potentially null) error openid-configuration value as per
   * <a href="https://tools.ietf.org/html/rfc7628#section-3.2.2">RFC 7628: A Set
   * of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth</a>.
   *
   * @return the (potentially null) error openid-configuration value
   */
  public String errorOpenIDConfiguration() {
    return errorOpenIDConfiguration;
  }

  /**
   * Set the token. The token value is unchanged and is expected to match the
   * provided token's value. All error values are cleared.
   *
   * @param token
   *            the mandatory token to set
   */
  public void token(OAuthBearerToken token) {
    this.token = Objects.requireNonNull(token);
    this.errorStatus = null;
    this.errorScope = null;
    this.errorOpenIDConfiguration = null;
  }

  /**
   * Set the error values as per
   * <a href="https://tools.ietf.org/html/rfc7628#section-3.2.2">RFC 7628: A Set
   * of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth</a>.
   * Any token is cleared.
   *
   * @param errorStatus
   *            the mandatory error status value from the <a href=
   *            "https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#extensions-error">IANA
   *            OAuth Extensions Error Registry</a> to set
   * @param errorScope
   *            the optional error scope value to set
   * @param errorOpenIDConfiguration
   *            the optional error openid-configuration value to set
   */
  public void error(String errorStatus, String errorScope, String errorOpenIDConfiguration) {
    if (Objects.requireNonNull(errorStatus).isEmpty())
      throw new IllegalArgumentException("error status must not be empty");
    this.errorStatus = errorStatus;
    this.errorScope = errorScope;
    this.errorOpenIDConfiguration = errorOpenIDConfiguration;
    this.token = null;
  }

}
