package org.cloudera.sasltestwork.oauthbearer.internals;

import java.security.Provider;
import java.security.Security;

public class OAuthBearerSaslClientProvider extends Provider {

  protected OAuthBearerSaslClientProvider() {
    super("SASL/OAUTHBEARER Client Provider", 1.0, "SASL/OAUTHBEARER Client Provider for HBase");
    put("SaslClientFactory.OAUTHBEARER",
        OAuthBearerSaslClientFactory.class.getName());
  }

  public static void initialize() {
    Security.addProvider(new OAuthBearerSaslClientProvider());
  }
}
