package org.cloudera.sasltestwork;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class SaslExtensions {
  /**
   * An "empty" instance indicating no SASL extensions
   */
  public static final SaslExtensions NO_SASL_EXTENSIONS = new SaslExtensions(Collections.emptyMap());
  private final Map<String, String> extensionsMap;

  public SaslExtensions(Map<String, String> extensionsMap) {
    this.extensionsMap = Collections.unmodifiableMap(new HashMap<>(extensionsMap));
  }

  /**
   * Returns an <strong>immutable</strong> map of the extension names and their values
   */
  public Map<String, String> map() {
    return extensionsMap;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    return extensionsMap.equals(((SaslExtensions) o).extensionsMap);
  }

  @Override
  public String toString() {
    return extensionsMap.toString();
  }

  @Override
  public int hashCode() {
    return extensionsMap.hashCode();
  }
}
