package com.example.rest;

import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class Util {
  private static final Logger log = Logger.getLogger("Util");

  /**
   * Reads a PEM file and returns the content as a byte array.
   * @param pemFile
   * @return a byte array containing the PEM file contents
   * @throws IOException
   */
  private static byte[] parsePEMFile(File pemFile) throws IOException {
    if (!pemFile.isFile() || !pemFile.exists()) {
      throw new FileNotFoundException(String.format("The file '%s' doesn't exist.",
                                      pemFile.getAbsolutePath()));
    }

    byte[] returnArray = new byte[0];

    try (PemReader reader = new PemReader(new FileReader(pemFile))) {
      PemObject pemObject = reader.readPemObject();

      if (null != pemObject) {
        returnArray = pemObject.getContent();
      }
    } catch (IOException e) {
      log.severe(e.toString());
      throw new IOException(e);
    }

    return returnArray;
  }

  /**
   * Reads a public key from a byte array and build a PublicKey object
   * using that key and the specified algorithm.
   * @param keyContents
   * @param algorithm
   * @return a PublicKey object based on the key and algorithm arguments
   * @throws IOException
   */
  public static PublicKey readPublicKeyFromArray(byte[] keyContents, String algorithm)
      throws IOException {
    // Need to massage the byte[] a bit here
    String KeyString = new String(keyContents);
    KeyString = KeyString.replaceAll("-----BEGIN PUBLIC KEY-----", "");
    KeyString = KeyString.replaceAll("-----END PUBLIC KEY-----", "");
    KeyString = KeyString.replaceAll("[\n\r]", "");
    KeyString = KeyString.trim();
    byte[] encoded = Base64.getDecoder().decode(KeyString);
    return getPublicKey(encoded, algorithm);
  }

  /**
   * Read a public key from a file path.
   * @param filepath
   * @param algorithm
   * @return a PublicKey object based on the key and algorithm arguments
   * @throws IOException
   */
  public static PublicKey readPublicKeyFromFile(String filepath, String algorithm)
      throws IOException {
    byte[] bytes = Util.parsePEMFile(new File(filepath));
    return Util.getPublicKey(bytes, algorithm);
  }


  /**
   * Create a public key from a byte array
   * @param keyBytes
   * @param algorithm
   * @return
   * @throws IOException
   */
  private static PublicKey getPublicKey(byte[] keyBytes, String algorithm)
                                                          throws IOException {
    PublicKey publicKey = null;
    try {
      KeyFactory kf = KeyFactory.getInstance(algorithm);
      EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
      publicKey = kf.generatePublic(keySpec);
    } catch (NoSuchAlgorithmException e) {
      log.severe("Could not reconstruct the public key, " +
                   "the given algorithm could not be found: " + e);
      throw new IOException(e);
    } catch (InvalidKeySpecException e) {
      log.severe("Could not reconstruct the public key: " + e);
      throw new IOException(e);
    }

    return publicKey;
  }

  /**
   * Extract a token from the set of headers in the list
   * @param headers
   * @return the bearer token, if one was found, or null if none was found
   */
  public static String getTokenFromHeaders(List<String> headers) {
    if (null == headers) {
      return null;
    }

    for (String header : headers) {
      log.info("\tfound header: " + header);
      if (header.contains("Bearer") || header.contains("bearer")) {
        log.info("token " + header);
        String token = Util.getTokenFromHeader(header);
        return token;
      }
    }
    return null;
  }

  /**
   * Extract just the token from the Authorization header
   * @param header
   * @return a String containg a token or null if there was an issue
   */
  public static String getTokenFromHeader(String header) {
    log.info("header: " + header);
    Pattern pattern = Pattern.compile("[bB]earer (.*)");
    Matcher matcher = pattern.matcher(header);
    if (matcher.find()) {
      log.info("Token is : " + matcher.group(1));
      return matcher.group(1);
    } else {
      log.info("No token foudnd in header");
      return null;
    }
  }
}
