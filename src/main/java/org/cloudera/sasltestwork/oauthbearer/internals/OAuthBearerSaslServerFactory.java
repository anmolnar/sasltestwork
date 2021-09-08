package org.cloudera.sasltestwork.oauthbearer.internals;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

public class OAuthBearerSaslServerFactory implements SaslServerFactory {
  @Override
  public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
    String[] mechanismNamesCompatibleWithPolicy = getMechanismNames(props);
    for (String s : mechanismNamesCompatibleWithPolicy) {
      if (s.equals(mechanism)) {
        return new OAuthBearerSaslServer(cbh);
      }
    }
    return null;
  }

  @Override
  public String[] getMechanismNames(Map<String, ?> props) {
    return new String[] { OAuthBearerSaslServer.MECHANISM };
  }
}
