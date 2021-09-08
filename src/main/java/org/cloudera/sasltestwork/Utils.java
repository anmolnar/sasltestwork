package org.cloudera.sasltestwork;

import java.util.HashMap;
import java.util.Map;

public class Utils {
  public static Map<String, String> parseMap(String mapStr, String keyValueSeparator, String elementSeparator) {
    Map<String, String> map = new HashMap<>();

    if (!mapStr.isEmpty()) {
      String[] attrvals = mapStr.split(elementSeparator);
      for (String attrval : attrvals) {
        String[] array = attrval.split(keyValueSeparator, 2);
        map.put(array[0], array[1]);
      }
    }
    return map;
  }

  public static <K, V> String mkString(Map<K, V> map, String begin, String end,
                                        String keyValueSeparator, String elementSeparator) {
    StringBuilder bld = new StringBuilder();
    bld.append(begin);
    String prefix = "";
    for (Map.Entry<K, V> entry : map.entrySet()) {
      bld.append(prefix).append(entry.getKey()).
          append(keyValueSeparator).append(entry.getValue());
      prefix = elementSeparator;
    }
    bld.append(end);
    return bld.toString();
  }

  /**
   * Checks if a string is null, empty or whitespace only.
   * @param str a string to be checked
   * @return true if the string is null, empty or whitespace only; otherwise, return false.
   */
  public static boolean isBlank(String str) {
    return str == null || str.trim().isEmpty();
  }
}
