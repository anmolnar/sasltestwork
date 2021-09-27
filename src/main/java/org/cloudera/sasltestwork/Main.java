package org.cloudera.sasltestwork;

import com.nimbusds.jose.jwk.JWKSet;
import org.cloudera.sasltestwork.oauthbearer.OAuthBearerToken;
import org.cloudera.sasltestwork.oauthbearer.internals.OAuthBearerSaslClientProvider;
import org.cloudera.sasltestwork.oauthbearer.internals.OAuthBearerSaslServerProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;

public class Main {
  private static final String MECHANISM = "OAUTHBEARER";
  private static final String SERVER_NAME = "myServer";
  private static final String PROTOCOL = "myProtocol";
  private static final String AUTHORIZATION_ID = null;
  private static final String QOP_LEVEL = "auth-conf";

  private static final Logger LOG = LoggerFactory.getLogger(Main.class);

  private static final String jwt = "<jwt>";

  static {
    OAuthBearerSaslServerProvider.initialize();
    OAuthBearerSaslClientProvider.initialize();
  }

  public static void main(String[] args) throws IOException, ParseException {
    LOG.info("Testing SASL...");

    JWKSet jwkSet =
        JWKSet.load(new File("/Users/andormolnar/work/jwt/jwks.json"));

    JwtServerCallbackhandler serverHandler = new JwtServerCallbackhandler(jwkSet);
    List<AppConfigurationEntry> jaasConfigEntries = new ArrayList<>();
    Map<String, String> options = new HashMap<>();
    //options.put("signedJwtValidatorRequiredScope", "burnyak");
    AppConfigurationEntry appConfigurationEntry =
        new AppConfigurationEntry("loginmodule", AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL, options);
    jaasConfigEntries.add(appConfigurationEntry);
    serverHandler.configure("OAUTHBEARER", jaasConfigEntries);

    OAuthBearerToken token = new OAuthBearerToken() {
      @Override
      public String value() {
        return jwt;
      }

      @Override
      public Set<String> scope() {
        return null;
      }

      @Override
      public long lifetimeMs() {
        return 0;
      }

      @Override
      public String principalName() {
        return null;
      }

      @Override
      public Long startTimeMs() {
        return null;
      }
    };
    JwtClientCallbackhandler clientHandler = new JwtClientCallbackhandler(token);

    Map<String, String> props = new HashMap<>();
    props.put(Sasl.QOP, QOP_LEVEL);

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

    response = saslClient.evaluateChallenge(new byte[0]);
    challenge = saslServer.evaluateResponse(response);
    response = saslClient.evaluateChallenge(challenge);

    System.out.println("Server isComplete = " + saslServer.isComplete());
    System.out.println("Client isComplete = " + saslClient.isComplete());
  }
}
