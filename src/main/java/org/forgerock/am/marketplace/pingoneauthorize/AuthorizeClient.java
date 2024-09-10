/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services.
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */
package org.forgerock.am.marketplace.pingoneauthorize;

import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashMap;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;


import org.forgerock.http.header.MalformedHeaderException;
import org.forgerock.http.header.authorization.BearerToken;
import org.forgerock.http.header.AuthorizationHeader;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Status;
import org.forgerock.http.Handler;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.integration.pingone.api.PingOneWorkerService;
import org.forgerock.services.context.RootContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service to integrate with PingOne Authorize APIs.
 */
@Singleton
public class AuthorizeClient {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizeClient.class);

    private static final String ENVIRONMENTS_PATH = "/environments/";
    private static final String DECISION_ENDPOINTS_PATH = "/decisionEndpoints/";

    private final Handler handler;

    /**
     * Creates a new instance that will close the underlying HTTP client upon shutdown.
     */
    @Inject
    public AuthorizeClient(@Named("CloseableHttpClientHandler") org.forgerock.http.Handler handler) {
        this.handler = handler;
    }

    /**
     * the POST {{apiPath}}/environments/{{envID}}/decisionEndpoints/{{decisionEndpointID}} executes
     * a decision request against the decision endpoint specified by its ID in the request URL.
     *
     * @param accessToken           The {@link AccessToken}
     * @param worker                The worker {@link PingOneWorkerService}
     * @param decisionEndpointID    The Decision Endpoint ID
     * @param decisionData          The data for the Parameters object
     * @return Json containing the response from the operation
     * @throws PingOneAuthorizeServiceException When API response != 201
     */
    public JsonValue p1AZEvaluateDecisionRequest(
        String accessToken,
        PingOneWorkerService.Worker worker,
        String decisionEndpointID,
        JsonValue decisionData) throws PingOneAuthorizeServiceException {

        // Create the request url
        Request request;

        URI uri = URI.create(
            worker.apiUrl() +
            ENVIRONMENTS_PATH + worker.environmentId() +
            DECISION_ENDPOINTS_PATH + decisionEndpointID);

        // Create the request body
        JsonValue parameters = json(object(1));
        parameters.put("parameters", decisionData);

        try {
            request = new Request().setUri(uri).setMethod("POST");
            request.getEntity().setJson(parameters);
            addAuthorizationHeader(request, accessToken);
            Response response = handler.handle(new RootContext(), request).getOrThrow();
            if (response.getStatus() == Status.CREATED || response.getStatus() == Status.OK) {
                return json(response.getEntity().getJson());
            } else {
                throw new PingOneAuthorizeServiceException("PingOne Authorize API response with error."
                                                        + response.getStatus()
                                                        + "-" + response.getEntity().getString());
            }
        } catch (MalformedHeaderException | InterruptedException | IOException e) {
            throw new PingOneAuthorizeServiceException("Failed to process client authorization" + e);
        }
    }

    /**
     * the POST {{apiPath}}/governance-engine operation authorizes the client using an individual request.
     *
     * @param pingAZEndpoint    The PingAuthorize Endpoint
     * @param accessToken       The Access Token
     * @param decisionData      The data for the Attributes object
     * @return Json containing the response from the operation
     * @throws PingAuthorizeServiceException When API response != 201
     */
    public JsonValue pingAZEvaluateDecisionRequest(
        String pingAZEndpoint,
        String accessToken,
        JsonValue decisionData) throws PingAuthorizeServiceException {

        // Create the request url
        Request request;
        URI uri = URI.create(
            pingAZEndpoint +
            "/governance-engine" );

        // Create the request body
        JsonValue body = json(object(1));
        body.put("attributes", decisionData);

        // Send the API request
        try {
            request = new Request().setUri(uri).setMethod("POST");
            request.getEntity().setJson(body);
            addAuthorizationHeader(request, accessToken);
            Response response = handler.handle(new RootContext(), request).getOrThrow();
            if (response.getStatus() == Status.CREATED || response.getStatus() == Status.OK) {
                return json(response.getEntity().getJson());
            } else {
                throw new PingAuthorizeServiceException("PingAuthorize API response with error."
                                                        + response.getStatus()
                                                        + "-" + response.getEntity().getString());
            }
        } catch (MalformedHeaderException | InterruptedException | IOException e) {
            throw new PingAuthorizeServiceException("Failed to process client authorization" + e);
        }
    }

    /**
     * Add the Authorization header to the request.
     *
     * @param request       The request to add the header
     * @param accessToken   The accessToken to add the header
     * @throws MalformedHeaderException When failed to add the header
     */
    private void addAuthorizationHeader(Request request, String accessToken) throws MalformedHeaderException {
        AuthorizationHeader header = new AuthorizationHeader();
        BearerToken bearerToken = new BearerToken(accessToken);
        header.setRawValue(BearerToken.NAME + " " + bearerToken.getToken());
        request.addHeaders(header);
    }
}
