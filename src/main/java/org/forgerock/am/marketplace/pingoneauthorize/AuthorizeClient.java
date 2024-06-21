/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */
package org.forgerock.am.marketplace.pingoneauthorize;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.LinkedHashMap;
import javax.inject.Inject;
import javax.inject.Singleton;

import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.http.HttpApplicationException;
import org.forgerock.http.handler.HttpClientHandler;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.thread.listener.ShutdownManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is a simple client for executing headless DaVinci flows.
 */
@Singleton
public class AuthorizeClient {

  private static final Logger logger = LoggerFactory.getLogger(AuthorizeClient.class);

  private static final String PINGONE_BASE_URL = "https://api.pingone";

  private final HttpClientHandler handler;

  /**
   * Creates a new instance that will close the underlying HTTP client upon shutdown.
   */
  @Inject
  public AuthorizeClient(ShutdownManager shutdownManager) throws HttpApplicationException {
    this.handler = new HttpClientHandler();
    shutdownManager.addShutdownListener(() -> {
      try {
        handler.close();
      } catch (IOException e) {
        logger.error("Could not close HTTP client", e);
      }
    });
  }

  /**
   * Executes a PingOne Authorization flow policy, returning the result or throwing an exception if there is an unexpected error.
   */
  public JsonValue p1AZEvaluateDecisionRequest(
          AccessToken accessToken,
          TNTPPingOneConfig tntpPingOneConfig,
          String decisionEndpointID,
          JsonValue decisionData) throws NodeProcessException {

    // Create the request url
    Request request = new Request();
    URI uri = URI.create(
            PINGONE_BASE_URL
            + tntpPingOneConfig.environmentRegion().getDomainSuffix()
            + "/v1/environments/"
            + tntpPingOneConfig.environmentId()
            + "/decisionEndpoints/"
            + decisionEndpointID
    );

    // Create the request data body
    JsonValue parameters = new JsonValue(new LinkedHashMap<String, Object>(1));
    parameters.put("parameters", decisionData);

    request.setUri(uri);
    request.setMethod("POST");
    request.addHeaders(new GenericHeader("Authorization", "Bearer " + accessToken));
    request.addHeaders(new GenericHeader("Accept", "application/json"));
    request.addHeaders(new GenericHeader("Content-Type", "application/json"));
    request.setEntity(parameters);

    // Send the API request
    try {
      logger.debug("Executing DaVinci decisionEndpointID={} in environmentId={}", decisionEndpointID, tntpPingOneConfig.environmentId());
      Response response = handler.handle(new RootContext(), request).getOrThrow();
      return new JsonValue(response.getEntity().getJson());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new NodeProcessException("Interrupted while sending request", e);
    } catch (IOException e) {
      throw new NodeProcessException("Encountered exception while getting JSON response", e);
    }
  }

  /**
   * Executes a Ping Authorization flow policy, returning the result or throwing an exception if there is an unexpected error.
   */
  public JsonValue pingAZEvaluateDecisionRequest(
          String pingAZEndpoint,
          String accessToken,
          JsonValue decisionData) throws NodeProcessException {

    // Create the request url
    Request request = new Request();
    URI uri = URI.create(
            pingAZEndpoint +
            "/governance-engine" );

    // Create the request data body
    JsonValue attributes = new JsonValue(new HashMap<String, Object>(1));
    attributes.put("attributes", decisionData);

    request.setUri(uri);
    request.setMethod("POST");
    request.addHeaders(new GenericHeader("Authorization", "Bearer " + accessToken));
    request.addHeaders(new GenericHeader("Accept", "application/json"));
    request.addHeaders(new GenericHeader("Content-Type", "application/json"));
    request.setEntity(attributes);

    // Send the API request
    try {
      logger.debug("Executing Ping Authorize Policy");
      Response response = handler.handle(new RootContext(), request).getOrThrow();
      return new JsonValue(response.getEntity().getJson());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new NodeProcessException("Interrupted while sending request", e);
    } catch (IOException e) {
      throw new NodeProcessException("Encountered exception while getting JSON response", e);
    }
  }
}
