package org.cloudera.sasltestwork.oauthbearer.internals.knox;

import java.io.Serializable;

public class OAuthBearerValidationResult implements Serializable {
  private static final long serialVersionUID = 5774669940899777373L;
  private final boolean success;
  private final String failureDescription;
  private final String failureScope;
  private final String failureOpenIdConfig;

  /**
   * Return an instance indicating success
   *
   * @return an instance indicating success
   */
  public static OAuthBearerValidationResult newSuccess() {
    return new OAuthBearerValidationResult(true, null, null, null);
  }

  /**
   * Return a new validation failure instance
   *
   * @param failureDescription
   *            optional description of the failure
   * @return a new validation failure instance
   */
  public static OAuthBearerValidationResult newFailure(String failureDescription) {
    return newFailure(failureDescription, null, null);
  }

  /**
   * Return a new validation failure instance
   *
   * @param failureDescription
   *            optional description of the failure
   * @param failureScope
   *            optional scope to be reported with the failure
   * @param failureOpenIdConfig
   *            optional OpenID Connect configuration to be reported with the
   *            failure
   * @return a new validation failure instance
   */
  public static OAuthBearerValidationResult newFailure(String failureDescription, String failureScope,
                                                       String failureOpenIdConfig) {
    return new OAuthBearerValidationResult(false, failureDescription, failureScope, failureOpenIdConfig);
  }

  private OAuthBearerValidationResult(boolean success, String failureDescription, String failureScope,
                                      String failureOpenIdConfig) {
    if (success && (failureScope != null || failureOpenIdConfig != null))
      throw new IllegalArgumentException("success was indicated but failure scope/OpenIdConfig were provided");
    this.success = success;
    this.failureDescription = failureDescription;
    this.failureScope = failureScope;
    this.failureOpenIdConfig = failureOpenIdConfig;
  }

  /**
   * Return true if this instance indicates success, otherwise false
   *
   * @return true if this instance indicates success, otherwise false
   */
  public boolean success() {
    return success;
  }

  /**
   * Return the (potentially null) descriptive message for the failure
   *
   * @return the (potentially null) descriptive message for the failure
   */
  public String failureDescription() {
    return failureDescription;
  }

  /**
   * Return the (potentially null) scope to be reported with the failure
   *
   * @return the (potentially null) scope to be reported with the failure
   */
  public String failureScope() {
    return failureScope;
  }

  /**
   * Return the (potentially null) OpenID Connect configuration to be reported
   * with the failure
   *
   * @return the (potentially null) OpenID Connect configuration to be reported
   *         with the failure
   */
  public String failureOpenIdConfig() {
    return failureOpenIdConfig;
  }

  /**
   * Raise an exception if this instance indicates failure, otherwise do nothing
   *
   * @throws OAuthBearerIllegalTokenException
   *             if this instance indicates failure
   */
  public void throwExceptionIfFailed() throws OAuthBearerIllegalTokenException {
    if (!success())
      throw new OAuthBearerIllegalTokenException(this);
  }
}
