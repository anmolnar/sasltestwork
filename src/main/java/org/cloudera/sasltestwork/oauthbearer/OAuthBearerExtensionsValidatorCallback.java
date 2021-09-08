package org.cloudera.sasltestwork.oauthbearer;

import org.cloudera.sasltestwork.SaslExtensions;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import javax.security.auth.callback.Callback;

public class OAuthBearerExtensionsValidatorCallback implements Callback {
  private final OAuthBearerToken token;
  private final SaslExtensions inputExtensions;
  private final Map<String, String> validatedExtensions = new HashMap<>();
  private final Map<String, String> invalidExtensions = new HashMap<>();

  public OAuthBearerExtensionsValidatorCallback(OAuthBearerToken token, SaslExtensions extensions) {
    this.token = Objects.requireNonNull(token);
    this.inputExtensions = Objects.requireNonNull(extensions);
  }

  /**
   * @return {@link OAuthBearerToken} the OAuth bearer token of the client
   */
  public OAuthBearerToken token() {
    return token;
  }

  /**
   * @return {@link SaslExtensions} consisting of the unvalidated extension names and values that were sent by the client
   */
  public SaslExtensions inputExtensions() {
    return inputExtensions;
  }

  /**
   * @return an unmodifiable {@link Map} consisting of the validated and recognized by the server extension names and values
   */
  public Map<String, String> validatedExtensions() {
    return Collections.unmodifiableMap(validatedExtensions);
  }

  /**
   * @return An immutable {@link Map} consisting of the name-&gt;error messages of extensions which failed validation
   */
  public Map<String, String> invalidExtensions() {
    return Collections.unmodifiableMap(invalidExtensions);
  }

  /**
   * Validates a specific extension in the original {@code inputExtensions} map
   * @param extensionName - the name of the extension which was validated
   */
  public void valid(String extensionName) {
    if (!inputExtensions.map().containsKey(extensionName))
      throw new IllegalArgumentException(String.format("Extension %s was not found in the original extensions", extensionName));
    validatedExtensions.put(extensionName, inputExtensions.map().get(extensionName));
  }
  /**
   * Set the error value for a specific extension key-value pair if validation has failed
   *
   * @param invalidExtensionName
   *            the mandatory extension name which caused the validation failure
   * @param errorMessage
   *            error message describing why the validation failed
   */
  public void error(String invalidExtensionName, String errorMessage) {
    if (Objects.requireNonNull(invalidExtensionName).isEmpty())
      throw new IllegalArgumentException("extension name must not be empty");
    this.invalidExtensions.put(invalidExtensionName, errorMessage);
  }
}
