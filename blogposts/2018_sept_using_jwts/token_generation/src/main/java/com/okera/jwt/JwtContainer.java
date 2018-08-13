package com.okera.jwt;

import java.util.Date;

public class JwtContainer {
  /**
   * This class is used as a data structure to hold the required information to create a
   * JWT token. Specific up-to-date details of each of the attributes can be found on
   * "www.jwt.io".
   */
  public final String jwtSubject;
  public final Date jwtExpirationTime;
  public final String jwtIssuer;
  public final String[] jwtGroup;
  public final String jwtAlgorithm;

  public boolean isValid = true;

  public JwtContainer(String subject, Date expirytime,
                      String issuer, String[] group, String algorithm) {
    this.jwtSubject = subject;
    this.jwtExpirationTime = expirytime;
    this.jwtIssuer = issuer;
    this.jwtGroup = group;
    this.jwtAlgorithm = algorithm;
  }

  public JwtContainer() {
    this.jwtSubject = null;
    this.jwtExpirationTime = null;
    this.jwtIssuer = null;
    this.jwtGroup = null;
    this.jwtAlgorithm = null;
    this.isValid = false;
  }
}
