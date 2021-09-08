package org.cloudera.sasltestwork.oauthbearer.internals;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

public class OAuthBearerSaslClient implements SaslClient {
  static final String MECHANISM = "OAUTHBEARER";
  public static final byte BYTE_CONTROL_A = (byte) 0x01;

  @Override
  public String getMechanismName() {
    return MECHANISM;
  }

  @Override
  public boolean hasInitialResponse() {
    return false;
  }

  @Override
  public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
    return new byte[0];
  }

  @Override
  public boolean isComplete() {
    return false;
  }

  @Override
  public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
    return new byte[0];
  }

  @Override
  public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
    return new byte[0];
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    return null;
  }

  @Override
  public void dispose() throws SaslException {

  }
}
