/*
 * Copyright 2024 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.am.marketplace.pingoneauthorize;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.am.marketplace.pingoneauthorize.PingOneAuthorizeNode.OutcomeProvider.CLIENT_ERROR_OUTCOME_ID;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import javax.security.auth.callback.Callback;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.integration.pingone.PingOneWorkerConfig;
import org.forgerock.openam.integration.pingone.PingOneWorkerException;
import org.forgerock.openam.integration.pingone.PingOneWorkerService;
import org.forgerock.openam.test.extensions.LoggerExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class PingOneAuthorizeNodeTest {

    @RegisterExtension
    public LoggerExtension loggerExtension = new LoggerExtension(PingOneAuthorizeNode.class);

    @Mock
    PingOneAuthorizeNode.Config config;

    @Mock
    PingOneWorkerService pingOneWorkerService;

    @Mock
    AccessToken accessToken;

    @Mock
    PingOneWorkerConfig.Worker worker;

    @Mock
    Realm realm;

    @Mock
    AuthorizeClient client;

    PingOneAuthorizeNode node;

    private static final String USER = "testUser";
    public static final String PINGONE_AUTHORIZE_ATTRIBUTE = "some-attribute-key";

    @BeforeEach
    public void setup() throws Exception {
        given(pingOneWorkerService.getWorker(any(), anyString())).willReturn(Optional.of(worker));
        given(pingOneWorkerService.getAccessToken(any(), any())).willReturn(accessToken);

        node = spy(new PingOneAuthorizeNode(config, realm, client));
    }

    @Test
    public void testPingOneUserIdNotFoundInSharedState() throws Exception {
        // Given
        JsonValue sharedState = json(object(field(USERNAME, USER), field(REALM, "/realm")));
        JsonValue transientState = json(object());

        // When
        Action result = node.process(getContext(sharedState, transientState, emptyList()));

        // Then
        assertThat(result.outcome).isEqualTo(CLIENT_ERROR_OUTCOME_ID);
    }

    @ParameterizedTest
    @CsvSource({
            "PERMIT,permit",
            "DENY,deny",
            "INDETERMINATE,indeterminate",
    })
    public void testReturnOutcomeP1Authorize(String decision, String expectedOutcome) throws Exception {
        // Given
        JsonValue sharedState = json(object(
                field(REALM, "/realm"),
                field(PINGONE_AUTHORIZE_ATTRIBUTE, "some-attribute-value")));

        given(config.attributeMap()).willReturn(Collections.singletonList(PINGONE_AUTHORIZE_ATTRIBUTE));

        JsonValue response = null;

        if (decision.equals("PERMIT")) {
            response = json(object(
                    field("decision", decision)));
        } else if (decision.equals("DENY")) {
            response = json(object(
                    field("decision", decision)));
        } else if (decision.equals("INDETERMINATE")) {
            response = json(object(
                    field("decision", decision)));
        }

        when(client.p1AZEvaluateDecisionRequest(any(), any(), anyString(), any())).thenReturn(response);

        // When
        Action result = node.process(getContext(sharedState, json(object()), emptyList()));

        // Then
        assertThat(result.outcome).isEqualTo(expectedOutcome);
    }

    @Test
    public void testPingOneCommunicationFailed() throws Exception {
        // Given
        given(pingOneWorkerService.getAccessToken(any(), any())).willReturn(null);
        given(pingOneWorkerService.getAccessToken(realm, worker)).willThrow(new PingOneWorkerException(""));
        JsonValue sharedState = json(object(
                field(USERNAME, USER),
                field(REALM, "/realm"),
                field(PINGONE_AUTHORIZE_ATTRIBUTE, "some-attribute-value")
                                           ));
        JsonValue transientState = json(object());

        // When
        Action result = node.process(getContext(sharedState, transientState, emptyList()));

        // Then
        assertThat(result.outcome).isEqualTo(CLIENT_ERROR_OUTCOME_ID);
    }

    private TreeContext getContext(JsonValue sharedState, JsonValue transientState,
                                   List<? extends Callback> callbacks) {
        return new TreeContext(sharedState, transientState, new ExternalRequestContext.Builder().build(), callbacks,
                               Optional.empty());
    }
}