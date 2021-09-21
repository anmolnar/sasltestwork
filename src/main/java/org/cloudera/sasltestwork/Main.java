package org.cloudera.sasltestwork;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import org.cloudera.sasltestwork.oauthbearer.internals.OAuthBearerClientInitialResponse;
import org.cloudera.sasltestwork.oauthbearer.internals.OAuthBearerSaslClientProvider;
import org.cloudera.sasltestwork.oauthbearer.internals.OAuthBearerSaslServerProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

public class Main {
  private static final String MECHANISM = "OAUTHBEARER";
  private static final String SERVER_NAME = "myServer";
  private static final String PROTOCOL = "myProtocol";
  private static final String AUTHORIZATION_ID = null;
  private static final String QOP_LEVEL = "auth-conf";

  private static final Logger LOG = LoggerFactory.getLogger(Main.class);

  static {
    OAuthBearerSaslServerProvider.initialize();
    OAuthBearerSaslClientProvider.initialize();
  }

  public static void main(String[] args) throws SaslException, JwkException, MalformedURLException {
    LOG.info("Testing SASL...");

    JwkProvider jwkProvider =
        new JwkProviderBuilder(new URL("file:////Users/andormolnar/work/jwt/jwks.json"))
        .build();

    JwtServerCallbackhandler serverHandler = new JwtServerCallbackhandler(jwkProvider);
    List<AppConfigurationEntry> jaasConfigEntries = new ArrayList<>();
    Map<String, String> options = new HashMap<>();
    AppConfigurationEntry appConfigurationEntry =
        new AppConfigurationEntry("loginmodule", AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL, options);
    jaasConfigEntries.add(appConfigurationEntry);
    serverHandler.configure("OAUTHBEARER", jaasConfigEntries);

    JwtClientCallbackhandler clientHandler = new JwtClientCallbackhandler();

    Map<String, String> props = new HashMap<>();
    props.put(Sasl.QOP, QOP_LEVEL);

    Enumeration<SaslServerFactory> enumSaslServerFactory = Sasl.getSaslServerFactories();
    while (enumSaslServerFactory.hasMoreElements()) {
      SaslServerFactory saslServerFactory = enumSaslServerFactory.nextElement();
      System.out.println("Mech: " + saslServerFactory.getMechanismNames(null)[0]);
    }

    SaslServer saslServer = Sasl.createSaslServer(
        MECHANISM,
        PROTOCOL,
        SERVER_NAME,
        props,
        serverHandler);

    SaslClient saslClient = Sasl.createSaslClient(
        new String[]{ MECHANISM },
        AUTHORIZATION_ID,
        PROTOCOL,
        SERVER_NAME,
        props,
        clientHandler);

    byte[] challenge;
    byte[] response;

    OAuthBearerClientInitialResponse r =
        new OAuthBearerClientInitialResponse(
            "<jwt>",
            null, null);
    System.out.println(new String(r.toBytes(), StandardCharsets.UTF_8));
    challenge = saslServer.evaluateResponse(r.toBytes());
    response = saslClient.evaluateChallenge(challenge);

    System.out.println("Server isComplete = " + saslServer.isComplete());
    System.out.println("Client isComplete = " + saslClient.isComplete());
  }
}
