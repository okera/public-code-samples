package com.example.rest;

import com.auth0.jwt.algorithms.Algorithm;
import java.io.IOException;
import java.io.InputStream;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import org.apache.commons.io.IOUtils;

@Path("/customers")
public class CustomerService<HttpServletRequest> {
  private final CopyOnWriteArrayList<Customer> cList = CustomerList.getInstance();
  private static final Logger log = Logger.getLogger("CustomerService");
  public static final InputStream PUBLIC_KEY_FILE_IS =
      CustomerService.class.getClassLoader().getResourceAsStream("id_rsa.pub");
  public static Algorithm algorithmSign = null;
  List<String> adminGroups_ =  new ArrayList<String>(Arrays.asList("admin", "superadmin"));

  private boolean userIsAdmin(String token) {
    return userInAdminGroup(JWTUtil.getGroupsFromToken(algorithmSign, token));
  }

  private boolean userInAdminGroup(List<String> userGroups) {
    for(String userGroup : userGroups) {
      if (adminGroups_.contains(userGroup)) {
        return true;
      }
    }
    return false;
  }

  public CustomerService() throws IllegalArgumentException, IOException {
    log.setLevel(Level.WARNING);

    if (algorithmSign == null) {
      log.info("creating algorithm sign object");
      byte[] publicKeyBytes = IOUtils.toByteArray(PUBLIC_KEY_FILE_IS);
      if (publicKeyBytes.length == 0) {
        throw new IOException("Couldn't read public key input stream");
      } else {
        log.info("Read public key: " + new String(publicKeyBytes));
      }
      algorithmSign = Algorithm.RSA512(
          (RSAKey) Util.readPublicKeyFromArray(publicKeyBytes, "RSA"));
    } else {
      log.info("algorithm sign already exists");
    }

  }

  @GET
  @Path("/status")
  @Produces(MediaType.TEXT_PLAIN)
  public String getStatus(@Context HttpHeaders headers) {
    return "Status: ok\n";
  }

  @GET
  @Path("/all")
  @Produces(MediaType.TEXT_PLAIN)
  public String getAllCustomers(@Context HttpHeaders headers) {

    // Get the token from the headers and validate it prior to processing
    // the request
    String token = Util.getTokenFromHeaders(
        headers.getRequestHeader(HttpHeaders.AUTHORIZATION));

    if (token == null || !JWTUtil.tokenIsValid(algorithmSign, token)) {
      log.info("Specified token is not valid");
      return "You are not authorized to view this content\n";
    }

    return "---Customer List---\n"
        + cList.stream()
        .map(c -> c.toString())
        .collect(Collectors.joining("\n")) + "\n";
  }

  @GET
  @Path("{id}")
  @Produces(MediaType.TEXT_PLAIN)
  public String getCustomer(@PathParam("id") long id,
                            @Context HttpHeaders headers) {
    String adminContent = "";

    // Get the token from the headers and validate it prior to processing
    // the request
    String token = Util.getTokenFromHeaders(
        headers.getRequestHeader(HttpHeaders.AUTHORIZATION));

    if (token == null || !JWTUtil.tokenIsValid(algorithmSign, token)) {
      log.info("Specified token is not valid");
      return "You are not authorized to view this content\n";
    }

    log.info("Looking for id: " + id);
    Optional<Customer> match = cList.stream()
        .filter(c -> c.getId() == id)
        .findFirst();

    // If there are no matches, return an empty result
    if (!match.isPresent()) {
      return "Customer not found\n";
    }

    if (token != null ) {
      // Only display user socials for admin users
      if (userIsAdmin(token)) {
        adminContent = "\n" + "SSN: " + match.get().getSsn() + "\n";
      }
    }

    return "---Customer---\n" + match.get().toString() + "\n" + adminContent;
  }
}
