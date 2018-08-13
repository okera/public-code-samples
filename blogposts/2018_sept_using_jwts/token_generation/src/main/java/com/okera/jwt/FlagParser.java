package com.okera.jwt;

import java.io.IOException;
import java.util.Date;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public class FlagParser {
  public static final String DEFAULT_ALGORITHM = "RS512";
  public static final String DEFAULT_ALGORITHM_KEY = "algorithm";
  public static final String DEFAULT_EXPIRY_TIME_KEY = "expirytime";
  public static final String DEFAULT_GROUP_KEY = "group";
  public static final String DEFAULT_HELP_KEY = "help";
  public static final String DEFAULT_ISSUER_KEY = "issuer";
  public static final String DEFAULT_SUBJECT_KEY = "subject";
  public static final String[] DEFAULT_TOKEN_GROUP = { "web_user", "philatelist", "cat_person" };
  public static final String DEFAULT_TOKEN_ISSUER = "okera.com";
  public static final String helpText = "./jwt_gen (-s|--subject) <arg> (-e|--expirytime)"
      + "<arg> [-a|--algorithm|-g|--group|-i|--issuer]";
  public static final Option helpOption = new Option("h", DEFAULT_HELP_KEY, false, "print this message");
  public static final Option subjectOption = new Option("s", DEFAULT_SUBJECT_KEY, true, "user subject");
  public static final Option groupOption = new Option("g", DEFAULT_GROUP_KEY, true, "group association");
  public static final Option algorithmOption = new Option("a", DEFAULT_ALGORITHM_KEY, true, "one of "
    + "RS256, RS384, RS512");
  public static final Option expiryOption = new Option("e", DEFAULT_EXPIRY_TIME_KEY, true, "token " +
    "expiration time in EPOCH time");
  public static final Option issuerOption = new Option("i", DEFAULT_ISSUER_KEY, true, "token issuer");

  public static JwtContainer parse(String[] args) throws IOException, NumberFormatException {
    CommandLineParser parser = new DefaultParser();
    HelpFormatter formatter = new HelpFormatter();
    CommandLine cmd;

    /* Create a set of options to ensure the help formatter will print the help text for all
    of the options.
    */
    Options helpOptions = new Options();
    helpOptions.addOption(helpOption);
    helpOptions.addOption(subjectOption);
    helpOptions.addOption(groupOption);
    helpOptions.addOption(algorithmOption);
    helpOptions.addOption(expiryOption);
    helpOptions.addOption(issuerOption);

    /* Create a set of options where the required options are mandatory for input.
    */
    subjectOption.setRequired(true);
    expiryOption.setRequired(true);
    Options parsingOptions = new Options();
    parsingOptions.addOption(helpOption);
    parsingOptions.addOption(subjectOption);
    parsingOptions.addOption(groupOption);
    parsingOptions.addOption(algorithmOption);
    parsingOptions.addOption(expiryOption);
    parsingOptions.addOption(issuerOption);

    JwtContainer container = null;
    try {
      /* Parse the command line twice to ensure the first will only check for the help
         option and ignore the fact that subject and expiry time are required flags. The second
         will enforce that rule as the user is not seeking help.
      */
      cmd = parser.parse(helpOptions, args);

      if (cmd.hasOption(DEFAULT_HELP_KEY)) {
        formatter.printHelp(helpText, parsingOptions);
        container = new JwtContainer();
        return container;
      }

      cmd = parser.parse(parsingOptions, args);
      String subject = cmd.getOptionValue(DEFAULT_SUBJECT_KEY);
      Date expirytime = new Date(Long.parseLong
                          (cmd.getOptionValue(DEFAULT_EXPIRY_TIME_KEY)));
      String issuer = cmd.hasOption(DEFAULT_ISSUER_KEY) ?
                      cmd.getOptionValue(DEFAULT_ISSUER_KEY) :
                      DEFAULT_TOKEN_ISSUER;
      String[] group = cmd.hasOption(DEFAULT_GROUP_KEY) ?
                       cmd.getOptionValue(DEFAULT_GROUP_KEY).split(",") :
                       DEFAULT_TOKEN_GROUP;
      String algorithm = cmd.hasOption(DEFAULT_ALGORITHM_KEY) ?
                         cmd.getOptionValue(DEFAULT_ALGORITHM_KEY) :
                         DEFAULT_ALGORITHM;
      container = new JwtContainer(subject, expirytime, issuer, group, algorithm);
    } catch (ParseException e) {
      throw new IOException(e + "\n" + "Please use the -h flag to see proper usage");
    } catch (NumberFormatException e) {
      throw new NumberFormatException("Please enter a valid expiry time" + "\n" +
          "Please use the -h flag to see proper usage");
    }
    return container;
  }
}
