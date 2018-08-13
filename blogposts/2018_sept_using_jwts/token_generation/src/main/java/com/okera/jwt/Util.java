package com.okera.jwt;

import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import org.apache.log4j.Logger;

public class Util {

  static Logger logger = Logger.getLogger(Util.class);

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
      logger.error(e);
    }

    return returnArray;
  }

  public static PublicKey readPublicKeyFromFile(byte[] keyContents, String algorithm)
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

  public static PrivateKey readPrivateKeyFromFile(byte[] keyContents, String algorithm)
      throws IOException {
    // Need to massage the byte[] a bit here
    String KeyString = new String(keyContents);
    KeyString = KeyString.replaceAll("-----BEGIN PRIVATE KEY-----", "");
    KeyString = KeyString.replaceAll("-----END PRIVATE KEY-----", "");
    KeyString = KeyString.replaceAll("[\n\r]", "");
    KeyString = KeyString.trim();
    byte[] encoded = Base64.getDecoder().decode(KeyString);

    return Util.getPrivateKey(encoded, algorithm);
  }

  public static PublicKey readPublicKeyFromFile(String filepath, String algorithm)
      throws IOException {
    byte[] bytes = Util.parsePEMFile(new File(filepath));
    return Util.getPublicKey(bytes, algorithm);
  }

  public static PrivateKey readPrivateKeyFromFile(String filepath, String algorithm)
      throws IOException {
    byte[] bytes = Util.parsePEMFile(new File(filepath));
    return Util.getPrivateKey(bytes, algorithm);
  }


  private static PublicKey getPublicKey(byte[] keyBytes, String algorithm)
                                                          throws IOException {
    PublicKey publicKey = null;
    try {
      KeyFactory kf = KeyFactory.getInstance(algorithm);
      EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
      publicKey = kf.generatePublic(keySpec);
    } catch (NoSuchAlgorithmException e) {
      logger.error("Could not reconstruct the public key, " +
                   "the given algorithm could not be found: " + e);
      throw new IOException(e);
    } catch (InvalidKeySpecException e) {
      logger.error("Could not reconstruct the public key: " + e);
      throw new IOException(e);
    }

    return publicKey;
  }

  private static PrivateKey getPrivateKey(byte[] keyBytes, String algorithm)
                                                            throws IOException {
    PrivateKey privateKey = null;
    try {
      KeyFactory kf = KeyFactory.getInstance(algorithm);
      EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
      privateKey = kf.generatePrivate(keySpec);
    } catch (NoSuchAlgorithmException e) {
      logger.error("Could not reconstruct the private key, " +
                   " the given algorithm could not be found: " + e);
      throw new IOException(e);
    } catch (InvalidKeySpecException e) {
      logger.error("Could not reconstruct the private key: " + e);
      throw new IOException(e);
    }

    return privateKey;
  }
}
