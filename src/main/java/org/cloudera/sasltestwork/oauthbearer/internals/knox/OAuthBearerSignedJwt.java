package org.cloudera.sasltestwork.oauthbearer.internals.knox;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jwt.SignedJWT;
import org.cloudera.sasltestwork.Utils;
import org.cloudera.sasltestwork.oauthbearer.OAuthBearerToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Signed JWT implementation for OAuth Bearer authentication mech of SASL.
 */
public class OAuthBearerSignedJwt implements OAuthBearerToken {
  private static final Logger LOG = LoggerFactory.getLogger(OAuthBearerSignedJwt.class);

  private final String compactSerialization;
  private final JWSHeader header;
  private final String principalClaimName;
  private final String scopeClaimName;
  private final Map<String, Object> claims;
  private final Set<String> scope;
  private final long lifetime;
  private final String principalName;
  private final Long startTimeMs;
  private final JwkProvider jwkProvider;

  /**
   * Constructor with the given principal and scope claim names
   *
   * @param compactSerialization
   *            the compact serialization to parse as a signed JWT
   * @param principalClaimName
   *            the required principal claim name
   * @param scopeClaimName
   *            the required scope claim name
   * @throws OAuthBearerIllegalTokenException
   *             if the compact serialization is not a valid JWT
   *             (meaning it did not have 3 dot-separated Base64URL sections
   *             with a digital signature; or the header or claims
   *             either are not valid Base 64 URL encoded values or are not JSON
   *             after decoding; or the mandatory '{@code alg}' header value is
   *             missing)
   */
  public OAuthBearerSignedJwt(String compactSerialization, String principalClaimName, String scopeClaimName,
                              JwkProvider jwkProvider)
      throws OAuthBearerIllegalTokenException, JwkException {
    this.jwkProvider = jwkProvider;
    try {
      this.compactSerialization = Objects.requireNonNull(compactSerialization);
      SignedJWT jwtToken = SignedJWT.parse(compactSerialization);
      validateToken(jwtToken);
      this.header = jwtToken.getHeader();
      this.claims = jwtToken.getJWTClaimsSet().getClaims();
    } catch (ParseException e) {
      throw new OAuthBearerIllegalTokenException(
          OAuthBearerValidationResult.newFailure("Unable to parse JWT token"));
    }

    this.principalClaimName = Objects.requireNonNull(principalClaimName).trim();
    if (this.principalClaimName.isEmpty())
      throw new IllegalArgumentException("Must specify a non-blank principal claim name");
    this.scopeClaimName = Objects.requireNonNull(scopeClaimName).trim();
    if (this.scopeClaimName.isEmpty())
      throw new IllegalArgumentException("Must specify a non-blank scope claim name");
    this.scope = calculateScope();
    Date expirationTimeSeconds = expirationTime();
    if (expirationTimeSeconds == null)
      throw new OAuthBearerIllegalTokenException(
          OAuthBearerValidationResult.newFailure("No expiration time in JWT"));
    lifetime = convertClaimTimeInSecondsToMs(expirationTimeSeconds);
    String principalName = claim(this.principalClaimName, String.class);
    if (Utils.isBlank(principalName))
      throw new OAuthBearerIllegalTokenException(OAuthBearerValidationResult
          .newFailure("No principal name in JWT claim: " + this.principalClaimName));
    this.principalName = principalName;
    this.startTimeMs = calculateStartTimeMs();
  }

  @Override
  public String value() {
    return compactSerialization;
  }

  @Override
  public String principalName() {
    return principalName;
  }

  @Override
  public Long startTimeMs() {
    return startTimeMs;
  }

  @Override
  public long lifetimeMs() {
    return lifetime;
  }

  @Override
  public Set<String> scope() throws OAuthBearerIllegalTokenException {
    return scope;
  }

  /**
   * Return the JWT Claim Set as a {@code Map}
   *
   * @return the (always non-null but possibly empty) claims
   */
  public Map<String, Object> claims() {
    return claims;
  }

  /**
   * Return the (always non-null/non-empty) principal claim name
   *
   * @return the (always non-null/non-empty) principal claim name
   */
  public String principalClaimName() {
    return principalClaimName;
  }

  /**
   * Return the (always non-null/non-empty) scope claim name
   *
   * @return the (always non-null/non-empty) scope claim name
   */
  public String scopeClaimName() {
    return scopeClaimName;
  }

  /**
   * Indicate if the claim exists and is the given type
   *
   * @param claimName
   *            the mandatory JWT claim name
   * @param type
   *            the mandatory type, which should either be String.class,
   *            Number.class, or List.class
   * @return true if the claim exists and is the given type, otherwise false
   */
  public boolean isClaimType(String claimName, Class<?> type) {
    Object value = rawClaim(claimName);
    Objects.requireNonNull(type);
    if (value == null)
      return false;
    if (type == String.class && value instanceof String)
      return true;
    if (type == Number.class && value instanceof Number)
      return true;
    return type == List.class && value instanceof List;
  }

  /**
   * Extract a claim of the given type
   *
   * @param claimName
   *            the mandatory JWT claim name
   * @param type
   *            the mandatory type, which must either be String.class,
   *            Number.class, or List.class
   * @return the claim if it exists, otherwise null
   * @throws OAuthBearerIllegalTokenException
   *             if the claim exists but is not the given type
   */
  public <T> T claim(String claimName, Class<T> type) throws OAuthBearerIllegalTokenException {
    Object value = rawClaim(claimName);
    try {
      return Objects.requireNonNull(type).cast(value);
    } catch (ClassCastException e) {
      throw new OAuthBearerIllegalTokenException(
          OAuthBearerValidationResult.newFailure(String.format("The '%s' claim was not of type %s: %s",
              claimName, type.getSimpleName(), value.getClass().getSimpleName())));
    }
  }

  /**
   * Extract a claim in its raw form
   *
   * @param claimName
   *            the mandatory JWT claim name
   * @return the raw claim value, if it exists, otherwise null
   */
  public Object rawClaim(String claimName) {
    return claims().get(Objects.requireNonNull(claimName));
  }

  /**
   * Return the
   * <a href="https://tools.ietf.org/html/rfc7519#section-4.1.4">Expiration
   * Time</a> claim
   *
   * @return the <a href=
   *         "https://tools.ietf.org/html/rfc7519#section-4.1.4">Expiration
   *         Time</a> claim if available, otherwise null
   * @throws OAuthBearerIllegalTokenException
   *             if the claim value is the incorrect type
   */
  public Date expirationTime() throws OAuthBearerIllegalTokenException {
    return claim("exp", Date.class);
  }

  /**
   * Return the <a href="https://tools.ietf.org/html/rfc7519#section-4.1.6">Issued
   * At</a> claim
   *
   * @return the
   *         <a href= "https://tools.ietf.org/html/rfc7519#section-4.1.6">Issued
   *         At</a> claim if available, otherwise null
   * @throws OAuthBearerIllegalTokenException
   *             if the claim value is the incorrect type
   */
  public Number issuedAt() throws OAuthBearerIllegalTokenException {
    return claim("iat", Number.class);
  }

  /**
   * Return the
   * <a href="https://tools.ietf.org/html/rfc7519#section-4.1.2">Subject</a> claim
   *
   * @return the <a href=
   *         "https://tools.ietf.org/html/rfc7519#section-4.1.2">Subject</a> claim
   *         if available, otherwise null
   * @throws OAuthBearerIllegalTokenException
   *             if the claim value is the incorrect type
   */
  public String subject() throws OAuthBearerIllegalTokenException {
    return claim("sub", String.class);
  }

  /**
   * Decode the given Base64URL-encoded value, parse the resulting JSON as a JSON
   * object, and return the map of member names to their values (each value being
   * represented as either a String, a Number, or a List of Strings).
   *
   * @param split
   *            the value to decode and parse
   * @return the map of JSON member names to their String, Number, or String List
   *         value
   * @throws OAuthBearerIllegalTokenException
   *             if the given Base64URL-encoded value cannot be decoded or parsed
   */
  public static Map<String, Object> toMap(String split) throws OAuthBearerIllegalTokenException {
    Map<String, Object> retval = new HashMap<>();
    try {
      byte[] decode = Base64.getDecoder().decode(split);
      JsonNode jsonNode = new ObjectMapper().readTree(decode);
      if (jsonNode == null)
        throw new OAuthBearerIllegalTokenException(OAuthBearerValidationResult.newFailure("malformed JSON"));
      for (Iterator<Map.Entry<String, JsonNode>> iterator = jsonNode.fields(); iterator.hasNext();) {
        Map.Entry<String, JsonNode> entry = iterator.next();
        retval.put(entry.getKey(), convert(entry.getValue()));
      }
      return Collections.unmodifiableMap(retval);
    } catch (IllegalArgumentException e) {
      // potentially thrown by java.util.Base64.Decoder implementations
      throw new OAuthBearerIllegalTokenException(
          OAuthBearerValidationResult.newFailure("malformed Base64 URL encoded value"));
    } catch (IOException e) {
      throw new OAuthBearerIllegalTokenException(OAuthBearerValidationResult.newFailure("malformed JSON"));
    }
  }

  private static Object convert(JsonNode value) {
    if (value.isArray()) {
      List<String> retvalList = new ArrayList<>();
      for (JsonNode arrayElement : value)
        retvalList.add(arrayElement.asText());
      return retvalList;
    }
    return value.getNodeType() == JsonNodeType.NUMBER ? value.numberValue() : value.asText();
  }

  private Long calculateStartTimeMs() throws OAuthBearerIllegalTokenException {
    Date issuedAtSeconds = claim("iat", Date.class);
    return issuedAtSeconds == null ? null : convertClaimTimeInSecondsToMs(issuedAtSeconds);
  }

  private static long convertClaimTimeInSecondsToMs(Date claimValue) {
    return Math.round(claimValue.getTime() * 1000);
  }

  private Set<String> calculateScope() {
    String scopeClaimName = scopeClaimName();
    if (isClaimType(scopeClaimName, String.class)) {
      String scopeClaimValue = claim(scopeClaimName, String.class);
      if (Utils.isBlank(scopeClaimValue))
        return Collections.emptySet();
      else {
        Set<String> retval = new HashSet<>();
        retval.add(scopeClaimValue.trim());
        return Collections.unmodifiableSet(retval);
      }
    }
    List<?> scopeClaimValue = claim(scopeClaimName, List.class);
    if (scopeClaimValue == null || scopeClaimValue.isEmpty())
      return Collections.emptySet();
    @SuppressWarnings("unchecked")
    List<String> stringList = (List<String>) scopeClaimValue;
    Set<String> retval = new HashSet<>();
    for (String scope : stringList) {
      if (!Utils.isBlank(scope)) {
        retval.add(scope.trim());
      }
    }
    return Collections.unmodifiableSet(retval);
  }

  /**
   * This method provides a single method for validating the JWT for use in
   * request processing. It provides for the override of specific aspects of
   * this implementation through submethods used within but also allows for the
   * override of the entire token validation algorithm.
   *
   * @param jwtToken the token to validate
   * @return true if valid
   */
  private void validateToken(SignedJWT jwtToken) throws JwkException {
    boolean sigValid = validateSignature(jwtToken);
    if (!sigValid) {
      throw new OAuthBearerIllegalTokenException(
          OAuthBearerValidationResult.newFailure("Invalid JWT: signature could not be verified"));
    }
//    boolean audValid = validateAudiences(jwtToken);
//    if (!audValid) {
//      throw new OAuthBearerIllegalTokenException(
//          OAuthBearerValidationResult.newFailure("Invalid JWT: audience validation failed"));
//    }
//    boolean expValid = validateExpiration(jwtToken);
//    if (!expValid) {
//      throw new OAuthBearerIllegalTokenException(
//          OAuthBearerValidationResult.newFailure("Invalid JWT: expiration validation failed"));
//    }
  }

  /**
   * Verify the signature of the JWT token in this method. This method depends
   * on the public key that was established during init based upon the
   * provisioned public key. Override this method in subclasses in order to
   * customize the signature verification behavior.
   *
   * @param jwtToken the token that contains the signature to be validated
   * @return valid true if signature verifies successfully; false otherwise
   */
  protected boolean validateSignature(SignedJWT jwtToken) throws JwkException {
    boolean valid = false;
    if (JWSObject.State.SIGNED == jwtToken.getState()) {
      LOG.debug("JWT token is in a SIGNED state");
      if (jwtToken.getSignature() != null) {
        LOG.debug("JWT token signature is not null");
        try {
          JWSVerifierFactory jwsVerifierFactory = new DefaultJWSVerifierFactory();
          JWSVerifier verifier = jwsVerifierFactory.createJWSVerifier(jwtToken.getHeader(),
              jwkProvider.get(jwtToken.getHeader().getKeyID()).getPublicKey());
          if (jwtToken.verify(verifier)) {
            valid = true;
            LOG.debug("JWT token has been successfully verified");
          } else {
            LOG.warn("JWT signature verification failed.");
          }
        } catch (JOSEException je) {
          LOG.warn("Error while validating signature", je);
        }
      }
    }
    return valid;
  }

}
