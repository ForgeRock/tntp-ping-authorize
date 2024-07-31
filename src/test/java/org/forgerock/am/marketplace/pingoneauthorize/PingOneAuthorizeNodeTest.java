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
import static org.forgerock.am.marketplace.pingoneauthorize.PingOneAuthorizeNode.STATEMENTCODESATTR;
import static org.forgerock.am.marketplace.pingoneauthorize.PingOneAuthorizeNode.USECONTINUEATTR;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.am.marketplace.pingoneauthorize.PingOneAuthorizeNode.OutcomeProvider.CLIENT_ERROR_OUTCOME_ID;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import javax.security.auth.callback.Callback;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.integration.pingone.PingOneWorkerConfig;
import org.forgerock.openam.integration.pingone.PingOneWorkerException;
import org.forgerock.openam.integration.pingone.PingOneWorkerService;
import org.forgerock.openam.test.extensions.LoggerExtension;
import org.forgerock.util.i18n.PreferredLocales;
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

        node = spy(new PingOneAuthorizeNode(config, realm, pingOneWorkerService, client));
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
    public void testReturnOutcomePingOneAuthorize(String decision, String expectedOutcome) throws Exception {
        // Given
        JsonValue sharedState = json(object(
                field(REALM, "/realm"),
                field(PINGONE_AUTHORIZE_ATTRIBUTE, "some-attribute-value")));

        given(config.decisionEndpointID()).willReturn("some-endpoint-id");
        given(config.attributeMap()).willReturn(Collections.singletonList(PINGONE_AUTHORIZE_ATTRIBUTE));
        given(config.statementCodes()).willReturn(Collections.singletonList("some-statement-codes"));
        given(config.useContinue()).willReturn(Boolean.valueOf("some-boolean-value"));

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

        when(client.p1AZEvaluateDecisionRequest(any(), any(), anyString(), json(any()))).thenReturn(response);

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

    @Test
    public void testGetInputs() {
        List<String> attributes = new ArrayList<>();
        attributes.add("some-attribute-value-1");
        attributes.add("some-attribute-value-2");

        given(config.attributeMap()).willReturn(attributes);

        InputState[] inputs = node.getInputs();

        assertThat(inputs[0].name).isEqualTo("some-attribute-value-1");
        assertThat(inputs[0].required).isEqualTo(false);

        assertThat(inputs[1].name).isEqualTo("some-attribute-value-2");
        assertThat(inputs[1].required).isEqualTo(false);
    }

    @Test
    public void testGetOutputs() {
        OutputState[] outputs = node.getOutputs();
        assertThat(outputs[0].name).isEqualTo("decision");
    }

    @Test
    public void testContinueGetOutcomes() throws Exception {
        PingOneAuthorizeNode.OutcomeProvider outcomeProvider = new PingOneAuthorizeNode.OutcomeProvider();

        JsonValue nodeAttributes = json(object(
            field(USECONTINUEATTR, true)));

        PreferredLocales locales = new PreferredLocales();
        List<OutcomeProvider.Outcome> outcomes = outcomeProvider.getOutcomes(locales, nodeAttributes);

        assertThat(outcomes.get(0).id).isEqualTo("continue");
        assertThat(outcomes.get(0).displayName).isEqualTo("Continue");

        assertThat(outcomes.get(1).id).isEqualTo("clientError");
        assertThat(outcomes.get(1).displayName).isEqualTo("Error");
    }

    @Test
    public void testWithoutContinueGetOutcomes() throws Exception {
        PingOneAuthorizeNode.OutcomeProvider outcomeProvider = new PingOneAuthorizeNode.OutcomeProvider();

        List<String> statementCodes = new ArrayList<>();
        statementCodes.add("approved");
        statementCodes.add("denied");

        JsonValue nodeAttributes = json(object(
            field(USECONTINUEATTR, false),
            field(STATEMENTCODESATTR, statementCodes)));

        PreferredLocales locales = new PreferredLocales();
        List<OutcomeProvider.Outcome> outcomes = outcomeProvider.getOutcomes(locales, nodeAttributes);

        assertThat(outcomes.get(0).id).isEqualTo("permit");
        assertThat(outcomes.get(0).displayName).isEqualTo("Permit");

        assertThat(outcomes.get(1).id).isEqualTo("deny");
        assertThat(outcomes.get(1).displayName).isEqualTo("Deny");

        assertThat(outcomes.get(2).id).isEqualTo("indeterminate");
        assertThat(outcomes.get(2).displayName).isEqualTo("Indeterminate");

        assertThat(outcomes.get(3).id).isEqualTo("approved");
        assertThat(outcomes.get(3).displayName).isEqualTo("approved");

        assertThat(outcomes.get(4).id).isEqualTo("denied");
        assertThat(outcomes.get(4).displayName).isEqualTo("denied");

        assertThat(outcomes.get(5).id).isEqualTo("clientError");
        assertThat(outcomes.get(5).displayName).isEqualTo("Error");
    }

    private TreeContext getContext(JsonValue sharedState, JsonValue transientState,
                                   List<? extends Callback> callbacks) {
        return new TreeContext(sharedState, transientState, new ExternalRequestContext.Builder().build(), callbacks,
                               Optional.empty());
    }
}