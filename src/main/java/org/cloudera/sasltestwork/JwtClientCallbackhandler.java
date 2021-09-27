package org.cloudera.sasltestwork;

import org.cloudera.sasltestwork.oauthbearer.OAuthBearerToken;
import org.cloudera.sasltestwork.oauthbearer.OAuthBearerTokenCallback;
import org.cloudera.sasltestwork.oauthbearer.SaslExtensionsCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.AccessController;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

public class JwtClientCallbackhandler implements CallbackHandler {
  private static final Logger LOG = LoggerFactory.getLogger(JwtClientCallbackhandler.class);
  private final OAuthBearerToken jwt;

  public JwtClientCallbackhandler(OAuthBearerToken jwt) {
    this.jwt = jwt;
  }

  @Override
  public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
    for (Callback callback : callbacks) {
      if (callback instanceof OAuthBearerTokenCallback)
        handleCallback((OAuthBearerTokenCallback) callback);
      else if (callback instanceof SaslExtensionsCallback)
        handleCallback((SaslExtensionsCallback) callback, Subject.getSubject(AccessController.getContext()));
      else
        throw new UnsupportedCallbackException(callback);
    }
  }

  private void handleCallback(OAuthBearerTokenCallback callback) {
    if (callback.token() != null)
      throw new IllegalArgumentException("Callback had a token already");
    callback.token(jwt);
  }

  /**
   * Attaches the first {@link SaslExtensions} found in the public credentials of the Subject
   */
  private static void handleCallback(SaslExtensionsCallback extensionsCallback, Subject subject) {
    if (subject != null && !subject.getPublicCredentials(SaslExtensions.class).isEmpty()) {
      SaslExtensions extensions = subject.getPublicCredentials(SaslExtensions.class).iterator().next();
      extensionsCallback.extensions(extensions);
    }
  }
}
