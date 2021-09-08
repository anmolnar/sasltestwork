package org.cloudera.sasltestwork.oauthbearer.internals;

import java.security.Provider;
import java.security.Security;

public class OAuthBearerSaslServerProvider extends Provider {

  protected OAuthBearerSaslServerProvider() {
    super("SASL/OAUTHBEARER Server Provider", 1.0, "SASL/OAUTHBEARER Server Provider for Kafka");
    put("SaslServerFactory.OAUTHBEARER", OAuthBearerSaslServerFactory.class.getName());
  }

  public static void initialize() {
    Security.addProvider(new OAuthBearerSaslServerProvider());
  }
}
