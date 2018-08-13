package com.okera.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.JWT;
import java.io.IOException;
import java.io.InputStream;
import java.security.interfaces.RSAKey;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;

/**
 * Utility to generate JWT a token. These are generated using our existing keys.
 */
public class JwtGenerator {
  // NOTE: these must be openssh keys NOT RSA keys
  public static final String GROUP_CLAIM_NAME = "groups";
  public static final InputStream PRIVATE_KEY_FILE_IS =
        JwtGenerator.class.getClassLoader().getResourceAsStream("id_rsa.priv");

  static Logger logger = Logger.getLogger(JwtGenerator.class);

  public static void main(String[] args) {
    try {
      // Add the bouncy castle provider
      java.security.Security.addProvider(new
          org.bouncycastle.jce.provider.BouncyCastleProvider());
      BasicConfigurator.configure();
      JwtContainer parameters = FlagParser.parse(args);
      if (parameters.isValid) {
        System.out.println(generateToken(parameters));
      }
    } catch (Exception e) {
      logger.error("IOException while creating token: " + e.getMessage());
      System.exit(1);
    }
  }

  public static String generateToken(JwtContainer userArgs) throws IOException {
    String token = "";
    try {
      Algorithm algorithmSign;
      switch (userArgs.jwtAlgorithm) {
        case "RS256":
          algorithmSign = Algorithm.RSA256((RSAKey)
              Util.readPrivateKeyFromFile(IOUtils.toByteArray(PRIVATE_KEY_FILE_IS), "RSA"));
          break;
        case "RS384":
          algorithmSign = Algorithm.RSA384((RSAKey)
              Util.readPrivateKeyFromFile(IOUtils.toByteArray(PRIVATE_KEY_FILE_IS), "RSA"));
          break;
        case "RS512":
          algorithmSign = Algorithm.RSA512((RSAKey)
              Util.readPrivateKeyFromFile(IOUtils.toByteArray(PRIVATE_KEY_FILE_IS), "RSA"));
          break;
        default:
          throw new UnsupportedOperationException();
      }

      token = JWT.create()
                 .withExpiresAt(userArgs.jwtExpirationTime)
                 .withIssuer(userArgs.jwtIssuer)
                 .withSubject(userArgs.jwtSubject)
                 .withArrayClaim(GROUP_CLAIM_NAME,  userArgs.jwtGroup)
                 .sign(algorithmSign);
    } catch (UnsupportedOperationException e) {
      throw new IOException("Incorrect encoding algorithm specified. You specified " +
      userArgs.jwtAlgorithm + " and the correct format is (RS256|RS384|RS512)");
    }
    return token;
  }
}
