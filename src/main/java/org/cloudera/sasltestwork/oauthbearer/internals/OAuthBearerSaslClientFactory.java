package org.cloudera.sasltestwork.oauthbearer.internals;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;

public class OAuthBearerSaslClientFactory implements SaslClientFactory {
  @Override
  public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName,
                                     Map<String, ?> props, CallbackHandler callbackHandler) {
    String[] mechanismNamesCompatibleWithPolicy = getMechanismNames(props);
    for (String mechanism : mechanisms) {
      for (String s : mechanismNamesCompatibleWithPolicy) {
        if (s.equals(mechanism)) {
          return new OAuthBearerSaslClient(callbackHandler);
        }
      }
    }
    return null;
  }

  @Override
  public String[] getMechanismNames(Map<String, ?> props) {
    return new String[] { OAuthBearerSaslClient.MECHANISM };
  }
}
