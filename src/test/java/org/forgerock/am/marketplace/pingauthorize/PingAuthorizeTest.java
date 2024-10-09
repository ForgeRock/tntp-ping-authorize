/*
 * Copyright 2024 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package org.forgerock.am.marketplace.pingauthorize;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.am.marketplace.pingauthorize.PingAuthorizeNode.OutcomeProvider.CONTINUE_OUTCOME_ID;

import static org.forgerock.am.marketplace.pingauthorize.PingAuthorizeNode.STATEMENTCODESATTR;
import static org.forgerock.am.marketplace.pingauthorize.PingAuthorizeNode.USECONTINUEATTR;
import static org.forgerock.json.JsonValue.*;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.when;

import javax.security.auth.callback.Callback;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
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
public class PingAuthorizeTest {

    @RegisterExtension
    public LoggerExtension loggerExtension = new LoggerExtension(PingAuthorizeNode.class);

    @Mock
    PingAuthorizeNode.Config config;

    @Mock
    Realm realm;

    @Mock
    PingAuthorizeService client;

    PingAuthorizeNode node;

    private static final String USER = "testUser";
    public static final String PINGONE_AUTHORIZE_ATTRIBUTE = "some-attribute-key";

    @BeforeEach
    public void setup() throws Exception {
        node = new PingAuthorizeNode(config, client);
    }

    @ParameterizedTest
    @CsvSource({
            "PERMIT,permit",
            "DENY,deny",
            "INDETERMINATE,indeterminate",
    })
    public void testReturnOutcomePingAuthorize(String decision, String expectedOutcome) throws Exception {
        // Given
        JsonValue sharedState = json(object(
                field(REALM, "/realm"),
                field(USERNAME, USER),
                field("some-access-token", "access-token-123")
                ));

        given(config.endpointUrl()).willReturn("some-endpoint-url");
        given(config.accessTokenAttribute()).willReturn("some-access-token");
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

        when(client.pingAZEvaluateDecisionRequest(any(), any(), json(any()))).thenReturn(response);

        // When
        Action result = node.process(getContext(sharedState, json(object()), emptyList()));

        // Then
        assertThat(result.outcome).isEqualTo(expectedOutcome);
    }

    @Test
    public void testStatementsPingOneAuthorize() throws Exception {
        // Given
        JsonValue sharedState = json(object(
                field(REALM, "/realm"),
                field(USERNAME, USER),
                field("some-access-token", "access-token-123")
        ));

        List<String> statementCodes = new ArrayList<>();
        statementCodes.add("REVIEW");
        statementCodes.add("DENIED");

        given(config.endpointUrl()).willReturn("some-endpoint-url");
        given(config.accessTokenAttribute()).willReturn("some-access-token");
        given(config.attributeMap()).willReturn(Collections.singletonList(PINGONE_AUTHORIZE_ATTRIBUTE));
        given(config.statementCodes()).willReturn(statementCodes);
        given(config.useContinue()).willReturn(false);

        JsonValue response = json(object(
                field("statements", array(
                        object(
                                field("code", "REVIEW")
                        )))));

        when(client.pingAZEvaluateDecisionRequest(any(), any(), json(any()))).thenReturn(response);

        // When
        Action result = node.process(getContext(sharedState, json(object()), emptyList()));

        // Then
        assertThat(result.outcome).isEqualTo("REVIEW");
    }

    @Test
    public void testUseContinuePingOneAuthorize() throws Exception {
        // Given
        JsonValue sharedState = json(object(
                field(REALM, "/realm"),
                field(USERNAME, USER),
                field("some-access-token", "access-token-123")
        ));

        List<String> statementCodes = new ArrayList<>();
        statementCodes.add("REVIEW");
        statementCodes.add("DENIED");

        given(config.endpointUrl()).willReturn("some-endpoint-url");
        given(config.accessTokenAttribute()).willReturn("some-access-token");
        given(config.attributeMap()).willReturn(Collections.singletonList(PINGONE_AUTHORIZE_ATTRIBUTE));
        given(config.statementCodes()).willReturn(statementCodes);
        given(config.useContinue()).willReturn(true);

        JsonValue response = json(object(
                field("statements", array(
                        object(
                                field("code", "REVIEW")
                        )))));

        when(client.pingAZEvaluateDecisionRequest(any(), any(), json(any()))).thenReturn(response);

        // When
        Action result = node.process(getContext(sharedState, json(object()), emptyList()));

        // Then
        assertThat(result.outcome).isEqualTo(CONTINUE_OUTCOME_ID);
    }

    @Test
    public void testGetInputs() {
        List<String> attributes = new ArrayList<>();
        attributes.add("some-attribute-value-1");
        attributes.add("some-attribute-value-2");

        given(config.attributeMap()).willReturn(attributes);
        given(config.accessTokenAttribute()).willReturn("some-access-token");

        InputState[] inputs = node.getInputs();

        assertThat(inputs[0].name).isEqualTo("some-access-token");
        assertThat(inputs[0].required).isEqualTo(true);

        assertThat(inputs[1].name).isEqualTo("some-attribute-value-1");
        assertThat(inputs[1].required).isEqualTo(false);

        assertThat(inputs[2].name).isEqualTo("some-attribute-value-2");
        assertThat(inputs[2].required).isEqualTo(false);
    }

    @Test
    public void testGetOutputs() {
        OutputState[] outputs = node.getOutputs();
        assertThat(outputs[0].name).isEqualTo("decision");
    }

    @Test
    public void testContinueGetOutcomes() throws Exception {
        PingAuthorizeNode.OutcomeProvider outcomeProvider = new PingAuthorizeNode.OutcomeProvider();

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
        PingAuthorizeNode.OutcomeProvider outcomeProvider = new PingAuthorizeNode.OutcomeProvider();

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
