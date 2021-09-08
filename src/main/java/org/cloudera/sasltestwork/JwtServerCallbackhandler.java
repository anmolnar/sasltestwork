package org.cloudera.sasltestwork;

import org.cloudera.sasltestwork.oauthbearer.OAuthBearerExtensionsValidatorCallback;
import org.cloudera.sasltestwork.oauthbearer.OAuthBearerValidatorCallback;
import org.cloudera.sasltestwork.oauthbearer.internals.OAuthBearerSaslServer;
import org.cloudera.sasltestwork.oauthbearer.internals.knox.OAuthBearerConfigException;
import org.cloudera.sasltestwork.oauthbearer.internals.knox.OAuthBearerIllegalTokenException;
import org.cloudera.sasltestwork.oauthbearer.internals.knox.OAuthBearerScopeUtils;
import org.cloudera.sasltestwork.oauthbearer.internals.knox.OAuthBearerSignedKnoxJwt;
import org.cloudera.sasltestwork.oauthbearer.internals.knox.OAuthBearerValidationResult;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

public class JwtServerCallbackhandler implements CallbackHandler {
  private static final Logger log = Logger.getLogger(Main.class.getName());

  private static final String OPTION_PREFIX = "unsecuredValidator";
  private static final String PRINCIPAL_CLAIM_NAME_OPTION = OPTION_PREFIX + "PrincipalClaimName";
  private static final String SCOPE_CLAIM_NAME_OPTION = OPTION_PREFIX + "ScopeClaimName";
  private static final String REQUIRED_SCOPE_OPTION = OPTION_PREFIX + "RequiredScope";
  private static final String ALLOWABLE_CLOCK_SKEW_MILLIS_OPTION = OPTION_PREFIX + "AllowableClockSkewMs";
  private Map<String, String> moduleOptions = null;
  private boolean configured = false;

  /**
   * Return true if this instance has been configured, otherwise false
   *
   * @return true if this instance has been configured, otherwise false
   */
  public boolean configured() {
    return configured;
  }

  @SuppressWarnings("unchecked")
  public void configure(String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
    if (!OAuthBearerSaslServer.MECHANISM.equals(saslMechanism))
      throw new IllegalArgumentException(String.format("Unexpected SASL mechanism: %s", saslMechanism));
    if (Objects.requireNonNull(jaasConfigEntries).size() != 1 || jaasConfigEntries.get(0) == null)
      throw new IllegalArgumentException(
          String.format("Must supply exactly 1 non-null JAAS mechanism configuration (size was %d)",
              jaasConfigEntries.size()));
    final Map<String, String> unmodifiableModuleOptions = Collections
        .unmodifiableMap((Map<String, String>) jaasConfigEntries.get(0).getOptions());
    this.moduleOptions = unmodifiableModuleOptions;
    configured = true;
  }

  @Override
  public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
    for (Callback callback : callbacks) {
      if (callback instanceof OAuthBearerValidatorCallback) {
        OAuthBearerValidatorCallback validationCallback = (OAuthBearerValidatorCallback) callback;
        try {
          handleCallback(validationCallback);
        } catch (OAuthBearerIllegalTokenException e) {
          OAuthBearerValidationResult failureReason = e.reason();
          String failureScope = failureReason.failureScope();
          validationCallback.error(failureScope != null ? "insufficient_scope" : "invalid_token",
              failureScope, failureReason.failureOpenIdConfig());
        }
      } else if (callback instanceof OAuthBearerExtensionsValidatorCallback) {
        OAuthBearerExtensionsValidatorCallback extensionsCallback = (OAuthBearerExtensionsValidatorCallback) callback;
        extensionsCallback.inputExtensions().map().forEach((extensionName, v) -> extensionsCallback.valid(extensionName));
      } else
        throw new UnsupportedCallbackException(callback);
    }
  }

  private void handleCallback(OAuthBearerValidatorCallback callback) {
    String tokenValue = callback.tokenValue();
    if (tokenValue == null)
      throw new IllegalArgumentException("Callback missing required token value");
    String principalClaimName = principalClaimName();
    String scopeClaimName = scopeClaimName();
    List<String> requiredScope = requiredScope();
    int allowableClockSkewMs = allowableClockSkewMs();
    OAuthBearerSignedKnoxJwt jwt = new OAuthBearerSignedKnoxJwt(tokenValue, principalClaimName, scopeClaimName);
    long now = System.currentTimeMillis();
//    OAuthBearerValidationUtils
//        .validateClaimForExistenceAndType(unsecuredJwt, true, principalClaimName, String.class)
//        .throwExceptionIfFailed();
//    OAuthBearerValidationUtils.validateIssuedAt(unsecuredJwt, false, now, allowableClockSkewMs)
//        .throwExceptionIfFailed();
//    OAuthBearerValidationUtils.validateExpirationTime(unsecuredJwt, now, allowableClockSkewMs)
//        .throwExceptionIfFailed();
//    OAuthBearerValidationUtils.validateTimeConsistency(unsecuredJwt).throwExceptionIfFailed();
//    OAuthBearerValidationUtils.validateScope(unsecuredJwt, requiredScope).throwExceptionIfFailed();
//    log.log(Level.INFO,"Successfully validated token with principal {}: {}", jwt.principalName(),
//        jwt.claims());
    callback.token(jwt);
  }

  private String principalClaimName() {
    String principalClaimNameValue = option(PRINCIPAL_CLAIM_NAME_OPTION);
    return Utils.isBlank(principalClaimNameValue) ? "sub" : principalClaimNameValue.trim();
  }

  private String scopeClaimName() {
    String scopeClaimNameValue = option(SCOPE_CLAIM_NAME_OPTION);
    return Utils.isBlank(scopeClaimNameValue) ? "scope" : scopeClaimNameValue.trim();
  }

  private List<String> requiredScope() {
    String requiredSpaceDelimitedScope = option(REQUIRED_SCOPE_OPTION);
    return Utils.isBlank(requiredSpaceDelimitedScope)
        ? Collections.emptyList()
        : OAuthBearerScopeUtils.parseScope(requiredSpaceDelimitedScope.trim());
  }

  private int allowableClockSkewMs() {
    String allowableClockSkewMsValue = option(ALLOWABLE_CLOCK_SKEW_MILLIS_OPTION);
    int allowableClockSkewMs = 0;
    try {
      allowableClockSkewMs = Utils.isBlank(allowableClockSkewMsValue) ? 0 : Integer.parseInt(allowableClockSkewMsValue.trim());
    } catch (NumberFormatException e) {
      throw new OAuthBearerConfigException(e.getMessage(), e);
    }
    if (allowableClockSkewMs < 0) {
      throw new OAuthBearerConfigException(
          String.format("Allowable clock skew millis must not be negative: %s", allowableClockSkewMsValue));
    }
    return allowableClockSkewMs;
  }

  private String option(String key) {
    if (!configured)
      throw new IllegalStateException("Callback handler not configured");
    return moduleOptions.get(Objects.requireNonNull(key));
  }

}
