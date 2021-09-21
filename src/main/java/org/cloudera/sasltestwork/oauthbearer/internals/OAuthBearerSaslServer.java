package org.cloudera.sasltestwork.oauthbearer.internals;

import org.cloudera.sasltestwork.SaslAuthenticationException;
import org.cloudera.sasltestwork.SaslExtensions;
import org.cloudera.sasltestwork.Utils;
import org.cloudera.sasltestwork.oauthbearer.OAuthBearerExtensionsValidatorCallback;
import org.cloudera.sasltestwork.oauthbearer.OAuthBearerToken;
import org.cloudera.sasltestwork.oauthbearer.OAuthBearerValidatorCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

public class OAuthBearerSaslServer implements SaslServer {
  private static final Logger LOG = LoggerFactory.getLogger(OAuthBearerSaslServer.class);

  public static final String MECHANISM = "OAUTHBEARER";
  private static final String INTERNAL_ERROR_ON_SERVER = "Authentication could not be performed due to an internal error on the server";

  private final CallbackHandler callbackHandler;
  private String errorMessage = null;
  private boolean complete;
  private SaslExtensions extensions;
  private OAuthBearerToken tokenForNegotiatedProperty = null;

  public OAuthBearerSaslServer(CallbackHandler callbackHandler) {
    this.callbackHandler = callbackHandler;
  }

  @Override
  public String getMechanismName() {
    return MECHANISM;
  }

  @Override
  public byte[] evaluateResponse(byte[] response) throws SaslException {
    if (response.length == 1 && response[0] == OAuthBearerSaslClient.BYTE_CONTROL_A && errorMessage != null) {
      LOG.info("Received %x01 response from client after it received our error");
      throw new SaslAuthenticationException(errorMessage);
    }
    errorMessage = null;

    OAuthBearerClientInitialResponse clientResponse;
    try {
      clientResponse = new OAuthBearerClientInitialResponse(response);
    } catch (SaslException e) {
      LOG.error("Unable to parse client initial response", e);
      throw e;
    }

    return process(clientResponse.tokenValue(), clientResponse.authorizationId(), clientResponse.extensions());
  }

  @Override
  public boolean isComplete() {
    return complete;
  }

  @Override
  public String getAuthorizationID() {
    if (!complete)
      throw new IllegalStateException("Authentication exchange has not completed");
    return tokenForNegotiatedProperty.principalName();
  }

  @Override
  public byte[] unwrap(byte[] incoming, int offset, int len) {
    if (!complete)
      throw new IllegalStateException("Authentication exchange has not completed");
    return Arrays.copyOfRange(incoming, offset, offset + len);
  }

  @Override
  public byte[] wrap(byte[] outgoing, int offset, int len) {
    if (!complete)
      throw new IllegalStateException("Authentication exchange has not completed");
    return Arrays.copyOfRange(outgoing, offset, offset + len);
  }

  @Override
  public void dispose() {
    complete = false;
    tokenForNegotiatedProperty = null;
    extensions = null;
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    return null;
  }

  private byte[] process(String tokenValue, String authorizationId, SaslExtensions extensions) throws SaslException {
    OAuthBearerValidatorCallback callback = new OAuthBearerValidatorCallback(tokenValue);
    try {
      callbackHandler.handle(new Callback[] {callback});
    } catch (IOException | UnsupportedCallbackException e) {
      handleCallbackError(e);
    }
    OAuthBearerToken token = callback.token();
    if (token == null) {
      errorMessage = jsonErrorResponse(callback.errorStatus(), callback.errorScope(),
          callback.errorOpenIDConfiguration());
      LOG.info(errorMessage);
      return errorMessage.getBytes(StandardCharsets.UTF_8);
    }
    /*
     * We support the client specifying an authorization ID as per the SASL
     * specification, but it must match the principal name if it is specified.
     */
    if (!authorizationId.isEmpty() && !authorizationId.equals(token.principalName()))
      throw new SaslAuthenticationException(String.format(
          "Authentication failed: Client requested an authorization id (%s) that is different from the token's principal name (%s)",
          authorizationId, token.principalName()));

    Map<String, String> validExtensions = processExtensions(token, extensions);

    tokenForNegotiatedProperty = token;
    this.extensions = new SaslExtensions(validExtensions);
    complete = true;
    LOG.info("Successfully authenticate User={}", token.principalName());
    return new byte[0];
  }

  private static String jsonErrorResponse(String errorStatus, String errorScope, String errorOpenIDConfiguration) {
    String jsonErrorResponse = String.format("{\"status\":\"%s\"", errorStatus);
    if (errorScope != null)
      jsonErrorResponse = String.format("%s, \"scope\":\"%s\"", jsonErrorResponse, errorScope);
    if (errorOpenIDConfiguration != null)
      jsonErrorResponse = String.format("%s, \"openid-configuration\":\"%s\"", jsonErrorResponse,
          errorOpenIDConfiguration);
    jsonErrorResponse = String.format("%s}", jsonErrorResponse);
    return jsonErrorResponse;
  }

  private void handleCallbackError(Exception e) throws SaslException {
    String msg = String.format("%s: %s", INTERNAL_ERROR_ON_SERVER, e.getMessage());
    LOG.error(msg, e);
    throw new SaslException(msg);
  }

  private Map<String, String> processExtensions(OAuthBearerToken token, SaslExtensions extensions) throws SaslException {
    OAuthBearerExtensionsValidatorCallback extensionsCallback = new OAuthBearerExtensionsValidatorCallback(token, extensions);
    try {
      callbackHandler.handle(new Callback[] {extensionsCallback});
    } catch (UnsupportedCallbackException e) {
      // backwards compatibility - no extensions will be added
    } catch (IOException e) {
      handleCallbackError(e);
    }
    if (!extensionsCallback.invalidExtensions().isEmpty()) {
      String errorMessage = String.format("Authentication failed: %d extensions are invalid! They are: %s",
          extensionsCallback.invalidExtensions().size(),
          Utils.mkString(extensionsCallback.invalidExtensions(), "", "", ": ", "; "));
      LOG.error(errorMessage);
      throw new SaslAuthenticationException(errorMessage);
    }

    return extensionsCallback.validatedExtensions();
  }
}
