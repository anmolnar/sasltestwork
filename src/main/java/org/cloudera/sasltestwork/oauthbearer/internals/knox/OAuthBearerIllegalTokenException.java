package org.cloudera.sasltestwork.oauthbearer.internals.knox;

import java.util.Objects;

public class OAuthBearerIllegalTokenException extends RuntimeException {
  private static final long serialVersionUID = -5275276640051316350L;
  private final OAuthBearerValidationResult reason;

  /**
   * Constructor
   *
   * @param reason
   *            the mandatory reason for the validation failure; it must indicate
   *            failure
   */
  public OAuthBearerIllegalTokenException(OAuthBearerValidationResult reason) {
    super(Objects.requireNonNull(reason).failureDescription());
    if (reason.success())
      throw new IllegalArgumentException("The reason indicates success; it must instead indicate failure");
    this.reason = reason;
  }

  /**
   * Return the (always non-null) reason for the validation failure
   *
   * @return the reason for the validation failure
   */
  public OAuthBearerValidationResult reason() {
    return reason;
  }
}
