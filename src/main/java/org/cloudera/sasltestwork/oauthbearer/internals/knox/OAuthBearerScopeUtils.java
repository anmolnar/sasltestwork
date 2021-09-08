package org.cloudera.sasltestwork.oauthbearer.internals.knox;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Utility class for help dealing with
 * <a href="https://tools.ietf.org/html/rfc6749#section-3.3">Access Token
 * Scopes</a>
 */
public class OAuthBearerScopeUtils {
  private static final Pattern INDIVIDUAL_SCOPE_ITEM_PATTERN = Pattern.compile("[\\x23-\\x5B\\x5D-\\x7E\\x21]+");

  /**
   * Return true if the given value meets the definition of a valid scope item as
   * per <a href="https://tools.ietf.org/html/rfc6749#section-3.3">RFC 6749
   * Section 3.3</a>, otherwise false
   *
   * @param scopeItem
   *            the mandatory scope item to check for validity
   * @return true if the given value meets the definition of a valid scope item,
   *         otherwise false
   */
  public static boolean isValidScopeItem(String scopeItem) {
    return INDIVIDUAL_SCOPE_ITEM_PATTERN.matcher(Objects.requireNonNull(scopeItem)).matches();
  }

  /**
   * Convert a space-delimited list of scope values (for example,
   * <code>"scope1 scope2"</code>) to a List containing the individual elements
   * (<code>"scope1"</code> and <code>"scope2"</code>)
   *
   * @param spaceDelimitedScope
   *            the mandatory (but possibly empty) space-delimited scope values,
   *            each of which must be valid according to
   *            {@link #isValidScopeItem(String)}
   * @return the list of the given (possibly empty) space-delimited values
   * @throws OAuthBearerConfigException
   *             if any of the individual scope values are malformed/illegal
   */
  public static List<String> parseScope(String spaceDelimitedScope) throws OAuthBearerConfigException {
    List<String> retval = new ArrayList<>();
    for (String individualScopeItem : Objects.requireNonNull(spaceDelimitedScope).split(" ")) {
      if (!individualScopeItem.isEmpty()) {
        if (!isValidScopeItem(individualScopeItem))
          throw new OAuthBearerConfigException(String.format("Invalid scope value: %s", individualScopeItem));
        retval.add(individualScopeItem);
      }
    }
    return Collections.unmodifiableList(retval);
  }

  private OAuthBearerScopeUtils() {
    // empty
  }
}
