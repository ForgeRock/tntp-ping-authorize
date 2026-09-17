/*
 * Copyright 2024 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.am.marketplace.pingauthorize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.PromiseImpl;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link PingAuthorizeService} request and lifecycle behaviour.
 */
public class PingAuthorizeServiceTest {

    private static final String ENDPOINT = "https://pingauthorize.example.com/endpoint";
    private static final String ACCESS_TOKEN = "access-token-123";

    @Test
    public void testConstructorBuildsPooledHandler() throws Exception {
        // When
        PingAuthorizeService service = new PingAuthorizeService();

        // Then
        assertThat(service).isNotNull();
        service.close();
    }

    @Test
    public void testCloseIsIdempotent() throws Exception {
        // Given
        PingAuthorizeService service = new PingAuthorizeService();

        // When
        service.close();
        service.close();

        // Then: no exception thrown
    }

    @Test
    public void testEvaluateDecisionReturnsJsonOnSuccess() throws Exception {
        // Given
        PromiseImpl<Response, NeverThrowsException> promise = PromiseImpl.create();
        Response okResponse = new Response(Status.OK).setEntity(json(object(
                field("decision", "PERMIT"))));
        ServiceAndRequest captured = newServiceWithHandler(() -> promise, okResponse);
        promise.handleResult(okResponse);

        // When
        JsonValue response = captured.service
                .pingAZEvaluateDecisionRequest(ENDPOINT, ACCESS_TOKEN, json(object()));

        // Then
        assertThat(response.get("decision").asString()).isEqualTo("PERMIT");
    }

    @Test
    public void testEvaluateDecisionThrowsOnErrorStatus() throws Exception {
        // Given
        PromiseImpl<Response, NeverThrowsException> promise = PromiseImpl.create();
        ServiceAndRequest captured = newServiceWithHandler(() -> promise,
                new Response(Status.FORBIDDEN).setEntity("forbidden"));
        promise.handleResult(new Response(Status.FORBIDDEN).setEntity("forbidden"));

        // When / Then
        assertThatThrownBy(() -> captured.service
                .pingAZEvaluateDecisionRequest(ENDPOINT, ACCESS_TOKEN, json(object())))
                .isInstanceOf(PingAuthorizeServiceException.class)
                .hasMessageContaining("403");
    }

    @Test
    public void testEvaluateDecisionBuildsRequestAndDoesNotLeakOnFailure() throws Exception {
        // Given
        PromiseImpl<Response, NeverThrowsException> promise = PromiseImpl.create();
        Response okResponse = new Response(Status.OK).setEntity(json(object()));
        ServiceAndRequest captured = newServiceWithHandler(() -> promise, okResponse);

        // When: the promise fails with a runtime exception (e.g. connection reset)
        promise.handleRuntimeException(new RuntimeException("connection reset"));
        assertThatThrownBy(() -> captured.service
                .pingAZEvaluateDecisionRequest(ENDPOINT, ACCESS_TOKEN, json(object())))
                .isInstanceOf(Exception.class);

        // Then: the captured request carried the expected method, path and Authorization header
        Request sent = captured.request;
        assertThat(sent.getMethod()).isEqualTo("POST");
        assertThat(sent.getUri().toString()).isEqualTo(ENDPOINT + "/governance-engine");
        assertThat(sent.getHeaders().getFirst("Authorization")).isEqualTo("Bearer " + ACCESS_TOKEN);

        // And: the service can still be closed safely
        captured.service.close();
    }

    private static ServiceAndRequest newServiceWithHandler(
            java.util.function.Supplier<Promise<Response, NeverThrowsException>> promiseSupplier,
            Response responseToClose) {
        ServiceAndRequest holder = new ServiceAndRequest();
        org.forgerock.http.Handler handler = (Context context, Request request) -> {
            holder.request = request;
            return promiseSupplier.get();
        };
        holder.service = new PingAuthorizeService(handler);
        return holder;
    }

    private static final class ServiceAndRequest {
        PingAuthorizeService service;
        Request request;
    }
}
