package org.cloudera.sasltestwork.oauthbearer;

import java.util.Set;

public interface OAuthBearerToken {
  /**
   * The <code>b64token</code> value as defined in
   * <a href="https://tools.ietf.org/html/rfc6750#section-2.1">RFC 6750 Section
   * 2.1</a>
   *
   * @return <code>b64token</code> value as defined in
   *         <a href="https://tools.ietf.org/html/rfc6750#section-2.1">RFC 6750
   *         Section 2.1</a>
   */
  String value();

  /**
   * The token's scope of access, as per
   * <a href="https://tools.ietf.org/html/rfc6749#section-1.4">RFC 6749 Section
   * 1.4</a>
   *
   * @return the token's (always non-null but potentially empty) scope of access,
   *         as per <a href="https://tools.ietf.org/html/rfc6749#section-1.4">RFC
   *         6749 Section 1.4</a>. Note that all values in the returned set will
   *         be trimmed of preceding and trailing whitespace, and the result will
   *         never contain the empty string.
   */
  Set<String> scope();

  /**
   * The token's lifetime, expressed as the number of milliseconds since the
   * epoch, as per <a href="https://tools.ietf.org/html/rfc6749#section-1.4">RFC
   * 6749 Section 1.4</a>
   *
   * @return the token'slifetime, expressed as the number of milliseconds since
   *         the epoch, as per
   *         <a href="https://tools.ietf.org/html/rfc6749#section-1.4">RFC 6749
   *         Section 1.4</a>.
   */
  long lifetimeMs();

  /**
   * The name of the principal to which this credential applies
   *
   * @return the always non-null/non-empty principal name
   */
  String principalName();

  /**
   * When the credential became valid, in terms of the number of milliseconds
   * since the epoch, if known, otherwise null. An expiring credential may not
   * necessarily indicate when it was created -- just when it expires -- so we
   * need to support a null return value here.
   *
   * @return the time when the credential became valid, in terms of the number of
   *         milliseconds since the epoch, if known, otherwise null
   */
  Long startTimeMs();
}
