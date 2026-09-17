/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services.
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */
package org.forgerock.am.marketplace.pingauthorize;

import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.io.IOException;
import java.net.URI;
import java.util.concurrent.TimeUnit;
import javax.inject.Inject;
import javax.inject.Singleton;

import org.forgerock.http.HttpApplicationException;
import org.forgerock.http.header.MalformedHeaderException;
import org.forgerock.http.header.authorization.BearerToken;
import org.forgerock.http.header.AuthorizationHeader;
import org.forgerock.http.handler.HttpClientHandler;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.Options;
import org.forgerock.util.time.Duration;

/**
 * Service to integrate with PingOne Authorize APIs.
 * <p>
 * The service owns a dedicated, pooled {@link HttpClientHandler} so that TLS connections to the
 * PingAuthorize endpoint are kept alive and reused across requests, instead of being torn down
 * (or competing for AM's shared client pool) on every call.
 */
@Singleton
public class PingAuthorizeService implements AutoCloseable {

    /**
     * Maximum number of pooled connections. The pool is dedicated to the PingAuthorize endpoint,
     * so a single route; both the total and per-route limits are set to this value.
     */
    private static final int MAX_CONNECTIONS = 32;

    /** Connect timeout. */
    private static final Duration CONNECT_TIMEOUT = Duration.duration(3, TimeUnit.SECONDS);

    /** Response (socket) timeout. */
    private static final Duration SO_TIMEOUT = Duration.duration(10, TimeUnit.SECONDS);

    private final org.forgerock.http.Handler handler;

    /**
     * Creates a new instance that will close the underlying HTTP client upon shutdown.
     */
    @Inject
    public PingAuthorizeService() throws HttpApplicationException {
        this(createDefaultHandler());
    }

    /**
     * Creates a new instance that will use the given HTTP handler. Intended for testing.
     *
     * @param handler the HTTP handler to use.
     */
    PingAuthorizeService(org.forgerock.http.Handler handler) {
        this.handler = handler;
    }

    private static HttpClientHandler createDefaultHandler() throws HttpApplicationException {
        return new HttpClientHandler(Options.defaultOptions()
                .set(HttpClientHandler.OPTION_REUSE_CONNECTIONS, true)
                .set(HttpClientHandler.OPTION_MAX_CONNECTIONS, MAX_CONNECTIONS)
                .set(HttpClientHandler.OPTION_POOLED_CONNECTION_TTL, -1L)
                .set(HttpClientHandler.OPTION_CONNECT_TIMEOUT, CONNECT_TIMEOUT)
                .set(HttpClientHandler.OPTION_SO_TIMEOUT, SO_TIMEOUT)
                .set(HttpClientHandler.OPTION_RETRY_REQUESTS, true));
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

        // Send the API request. The response is always closed (in the finally block) so that the
        // underlying TLS connection is released back to the pool and can be kept alive for reuse.
        Response response = null;
        try {
            request = new Request().setUri(uri).setMethod("POST");
            request.getEntity().setJson(body);
            addAuthorizationHeader(request, accessToken);
            response = handler.handle(new RootContext(), request).getOrThrow();
            if (response.getStatus() == Status.CREATED || response.getStatus() == Status.OK) {
                return json(response.getEntity().getJson());
            } else {
                throw new PingAuthorizeServiceException("PingAuthorize API response with error."
                                                        + response.getStatus()
                                                        + "-" + response.getEntity().getString());
            }
        } catch (MalformedHeaderException | InterruptedException | IOException e) {
            throw new PingAuthorizeServiceException("Failed to process client authorization" + e);
        } finally {
            if (response != null) {
                response.close();
            }
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

    /**
     * Closes the underlying HTTP client, releasing all pooled connections. Safe to call more than once.
     */
    @Override
    public void close() {
        if (handler instanceof AutoCloseable) {
            try {
                ((AutoCloseable) handler).close();
            } catch (Exception e) {
                // Nothing useful can be done at this point; closing must not throw.
            }
        }
    }
}
