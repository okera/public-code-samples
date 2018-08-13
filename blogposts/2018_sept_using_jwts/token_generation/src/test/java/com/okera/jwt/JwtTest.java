package com.okera.jwt;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Date;
import org.junit.BeforeClass;
import org.junit.Test;

public class JwtTest {
  public static final String CORRECT_ALGORITHM_STRING = "RS384";
  // Monday, May 18, 2099 4:46:47 PM
  public static final String EXPIRATION_STRING = "4082806007";
  public static final Date CORRECT_EXPIRATION_DATE = new Date(Long.parseLong(EXPIRATION_STRING));
  public static final String GROUP_STRING = "cat_person,seahawks_fan,bicyclist";
  public static final String[] GROUP_STRING_ARRAY = GROUP_STRING.split(",");;
  public static final String INCORRECT_ALGORITHM_STRING = "Incorrect Algorithm";
  public static final String ISSUER_STRING = "Okera";
  public static final String SUBJECT_STRING = "John Doe";

  @BeforeClass
  public static void init() {
    org.apache.log4j.BasicConfigurator.configure();
  }


  @Test
  public void parseOnlyRequiredParameters() {
    /**
     * Test a basic query where the user provides only the required parameters
     * (subject and expiration time). Test to ensure that other fields are auto
     * populated and a container is successfully returned.
     */
    try {
      String args[] = new String[] { "-s", SUBJECT_STRING,
          "-e", EXPIRATION_STRING };
      JwtContainer parsedOutput = FlagParser.parse(args);
      assertEquals(SUBJECT_STRING, parsedOutput.jwtSubject);
      assertEquals(CORRECT_EXPIRATION_DATE, parsedOutput.jwtExpirationTime);
    } catch (IOException e){
      fail();
    }

  }

  @Test
  public void parseAllParameters() throws IOException {
    String args[] = new String[] { "-s", SUBJECT_STRING,
                                   "-e", EXPIRATION_STRING,
                                   "-g", GROUP_STRING,
                                   "-i", ISSUER_STRING,
                                   "-a", CORRECT_ALGORITHM_STRING};

    JwtContainer parsedOutput = FlagParser.parse(args);
    assertEquals(SUBJECT_STRING, parsedOutput.jwtSubject);
    assertEquals(CORRECT_EXPIRATION_DATE, parsedOutput.jwtExpirationTime);
    assertArrayEquals(GROUP_STRING_ARRAY, parsedOutput.jwtGroup);
    assertEquals(ISSUER_STRING, parsedOutput.jwtIssuer);
    assertEquals(CORRECT_ALGORITHM_STRING, parsedOutput.jwtAlgorithm);
  }

  @Test
  public void parseIncorrectAlgorithm() {
    JwtContainer testingContainer = new JwtContainer(SUBJECT_STRING,
                                                    CORRECT_EXPIRATION_DATE,
                                                    ISSUER_STRING,
                                                    GROUP_STRING_ARRAY,
                                                    INCORRECT_ALGORITHM_STRING);
    /**
     * This test case has an expected code path that throws an exception and passes
     * the test case in the catch. There is a fail outside of the catch block because
     * we want to verify that the preceding line always throws an exception.
     */
    try {
      JwtGenerator.generateToken(testingContainer);
      fail();
    } catch (Exception e) {
    }
  }

  @Test
  public void parseNoRequiredOptions(){
    /**
     * This test case ensures the parser ensures the required parameters are given by the
     * user. There is a fail if the parser is successful or if the parser attempts to
     * convert "null" into a long which would mean the subject and expiry were not required.
     */
    try {
      String args[] = new String[] {"-i", ISSUER_STRING};
      FlagParser.parse(args);
      fail();
    } catch (NumberFormatException e) {
      fail();
    } catch (IOException e){
    }
  }
}
