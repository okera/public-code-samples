package com.example.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;


/**
 * Utility functions for interacting with JSON Web Tokens (JWT)
 */
public class JWTUtil {
  private static final Logger log = Logger.getLogger("JWTUtil");

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
   * Convert the value in the provided claim into a List of Strings.
   *
   * @param claim
   * @return the value of the provided claim, as a List of Strings
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
   * Validate the token and then pull out the username.
   *
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
   * Validate a token and then pull the groups value out.
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
