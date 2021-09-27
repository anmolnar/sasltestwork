package org.cloudera.sasltestwork;

import com.nimbusds.jose.jwk.JWKSet;
import org.cloudera.sasltestwork.oauthbearer.internals.OAuthBearerClientInitialResponse;
import org.cloudera.sasltestwork.oauthbearer.internals.OAuthBearerSaslClientProvider;
import org.cloudera.sasltestwork.oauthbearer.internals.OAuthBearerSaslServerProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
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

  public static void main(String[] args) throws IOException, ParseException {
    LOG.info("Testing SASL...");

    JWKSet jwkSet =
        JWKSet.load(new File("/Users/andormolnar/work/jwt/jwks.json"));

    JwtServerCallbackhandler serverHandler = new JwtServerCallbackhandler(jwkSet);
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
            "eyJqa3UiOiJodHRwczpcL1wvY29kLTcyMTEtZ2F0ZXdheS5jb2QtNzIxMS54Y3UyLTh5OHguZGV2LmNsZHIud29ya1wvY29kLTcyMTFcL2hvbWVwYWdlXC9rbm94dG9rZW5cL2FwaVwvdjFcL2p3a3MuanNvbiIsImtpZCI6IldTTTJpQlpiTG9HQzBBVGFyeWg1VjlFY3ZTdWR6Ml9VNnNqdDlvNkFWeDAiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjc3NvX2FuZG9yIiwiYXVkIjoiY2RwLXByb3h5LXRva2VuIiwiamt1IjoiaHR0cHM6XC9cL2NvZC03MjExLWdhdGV3YXkuY29kLTcyMTEueGN1Mi04eTh4LmRldi5jbGRyLndvcmtcL2NvZC03MjExXC9ob21lcGFnZVwva25veHRva2VuXC9hcGlcL3YxXC9qd2tzLmpzb24iLCJraWQiOiJXU00yaUJaYkxvR0MwQVRhcnloNVY5RWN2U3VkejJfVTZzanQ5bzZBVngwIiwiaXNzIjoiS05PWFNTTyIsImV4cCI6MTYzMjE0ODA4OSwibWFuYWdlZC50b2tlbiI6InRydWUiLCJrbm94LmlkIjoiYWM1ZTZiYzMtYzZkNi00NThjLWIyZjEtNGM4YjIwYTdkZjRjIn0.aNI8VkAQm2YD9ONI-JK15f0XXDkBXZ5k8o5FWxoYkli7vWYBg6uMG-G7RrzjqtPAdA9XbWQjMGBnX-jjJoC0BYv3xDGJDdX6DJFKgSdohjBoLwJFduiU_AGVcooZEaEtI6KUjySs5G7prk94ro-ftsgmHDPJw4ojvWX6r2n0Ah7sT05Yqw8ovupQWRbonVT7Wvhzjjc8vKdwi1HG1xE09k7VS8k2y20hc0gX1mdfgWR_fSwnWIzx4peMt7UJgoC7tqT7B-zX8zT2h0h_TsDj1egfNxVIKmvIsOUgoa09EtAt3XPXXdiBAmEoQaeJBg8QZMup-VcFHtJM0ttvnocEAg",
            null, null);
    System.out.println(new String(r.toBytes(), StandardCharsets.UTF_8));
    challenge = saslServer.evaluateResponse(r.toBytes());
    response = saslClient.evaluateChallenge(challenge);

    System.out.println("Server isComplete = " + saslServer.isComplete());
    System.out.println("Client isComplete = " + saslClient.isComplete());
  }
}
