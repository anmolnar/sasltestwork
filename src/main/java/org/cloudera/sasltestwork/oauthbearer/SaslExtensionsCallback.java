package org.cloudera.sasltestwork.oauthbearer;

import org.cloudera.sasltestwork.SaslExtensions;

import java.util.Objects;

import javax.security.auth.callback.Callback;

/**
 * Optional callback used for SASL mechanisms if any extensions need to be set
 * in the SASL exchange.
 */
public class SaslExtensionsCallback implements Callback {
  private SaslExtensions extensions = SaslExtensions.NO_SASL_EXTENSIONS;

  /**
   * Returns always non-null {@link SaslExtensions} consisting of the extension
   * names and values that are sent by the client to the server in the initial
   * client SASL authentication message. The default value is
   * {@link SaslExtensions#NO_SASL_EXTENSIONS} so that if this callback is
   * unhandled the client will see a non-null value.
   */
  public SaslExtensions extensions() {
    return extensions;
  }

  /**
   * Sets the SASL extensions on this callback.
   *
   * @param extensions
   *            the mandatory extensions to set
   */
  public void extensions(SaslExtensions extensions) {
    this.extensions = Objects.requireNonNull(extensions, "extensions must not be null");
  }
}
