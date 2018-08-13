package com.example.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;


/**
 * Utility functions for interacting with JSON Web Tokens (JWT)
 */
public class JWTUtil {
  private static final Logger log = Logger.getLogger("JWTUtil");

  /**
    * Use the indicated algorithm to build a PublicKey object from the supplied byte
    * array. Will throw an exception if the specified algorithm is not supported or if the
    * bytes provided do not conform to the expected format.
    */
  private static PublicKey getPublicKey(byte[] keyBytes, String algorithm)
      throws IOException {
    PublicKey publicKey = null;
    try {
      KeyFactory kf = KeyFactory.getInstance(algorithm);
      EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
      publicKey = kf.generatePublic(keySpec);
    } catch (NoSuchAlgorithmException e) {
      log.severe("Could not reconstruct the public key, unknown algorithm: " +
                    algorithm + " : " + e.toString());
      throw new IOException(e);
    } catch (InvalidKeySpecException e) {
      log.severe("Supplied public key bytes are not in the expected format. " +
          e.toString());
      throw new IOException(e);
    }

    return publicKey;
  }

  /**
   * Returns the user from the jwt token. This is typically the 'sub' claim but can be
   * custom.
   */
  public static String getUsername(DecodedJWT jwt) {
    // If none of the custom claims were found, return the default claim
    return jwt.getSubject();
  }

  /**
   * Pulls the value associated with the "groups" claim.
   *
   * @param jwt
   * @return list of groups that this user is a part of
   */
  public static List<String> getGroupsFromJWT(DecodedJWT jwt) {
    List<String> groups = JWTUtil.parseGroupsList(jwt.getClaim("groups"));
    return groups;
  }

  /**
   * Returns the decoded token without verifying it. This is useful for error reporting
   * or just looking at the claims that are public.
   */
  private static DecodedJWT getUnverifiedDecodedToken(String token) {
    String untrustedJwtString = removeSignatureFromToken(token);
    return JWT.decode(untrustedJwtString);
  }

  /**
   * Remove all text from the final period, onward, from this string.
   */
  private static String removeSignatureFromToken(String token) {
    int i = token.lastIndexOf('.');
    return token.substring(0, i + 1);
  }

  /**
   * Parses the groups from the claim if it is expected to be a list.
   */
  private static List<String> parseGroupsList(Claim claim) {
    List<String> result = new ArrayList<String>();
    if (claim == null) return result;
    List<String> groups = claim.asList(String.class);
    if (groups == null) return result;
    for (String group: groups) {
      result.add(group.toLowerCase());
    }
    return result;
  }

  /**
   * Verify a token using the configured public key.
   *
   * @param algorithmSign
   * @param token
   * @return boolean indicating whether the token argument is valid given the
   * algorithm object passed in.
   */
  public static boolean tokenIsValid(Algorithm algorithmSign, String token) {
    try {
      getUsernameFromToken(algorithmSign, token);
    } catch (JWTVerificationException e) {
      log.info("Could not validate token: " + token);
      return false;
    }
    return true;
  }

  /**
   * Pull the username out of a token after validating said token
   * @param algorithmSign
   * @param token
   * @return the value associated with the "sub" claim in the token
   * @throws JWTVerificationException
   */
  public static String getUsernameFromToken(Algorithm algorithmSign, String token)
      throws JWTVerificationException {
    String subject = "";
    DecodedJWT jwt = JWT.require(algorithmSign).build().verify(token);
    subject = JWTUtil.getUsername(jwt);
    return subject;
  }

  /**
   * Pull the groups out of a token after validating said token
   *
   * @param algorithmSign
   * @param token
   * @return the value associated with the "groups" claim
   */
  public static List<String> getGroupsFromToken(Algorithm algorithmSign, String token) {
    DecodedJWT jwt = JWT.require(algorithmSign).build().verify(token);
    List<String> groups = JWTUtil.getGroupsFromJWT(jwt);
    log.info("token has username: " + groups);

    return groups;
  }
}
