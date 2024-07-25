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
import static org.mockito.ArgumentMatchers.anyObject;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class PingAuthorizeTest {

    private static final Logger log = LoggerFactory.getLogger(PingOneAuthorizeNodeTest.class);
    @RegisterExtension
    public LoggerExtension loggerExtension = new LoggerExtension(PingOneAuthorizeNode.class);

    @Mock
    PingAuthorizeNode.Config config;

    @Mock
    Realm realm;

    @Mock
    AuthorizeClient client;

    PingAuthorizeNode node;

    private static final String USER = "testUser";
    public static final String PINGONE_AUTHORIZE_ATTRIBUTE = "some-attribute-key";

    @BeforeEach
    public void setup() throws Exception {
        node = spy(new PingAuthorizeNode(config, realm, client));
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

        System.out.println("\n");
        System.out.println("decision: " + decision);
        System.out.println("expected outcome: " + expectedOutcome);

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

        System.out.println("response" + response);
        System.out.println("\n");

        when(client.pingAZEvaluateDecisionRequest(any(), any(), json(any()))).thenReturn(response);

        // When
        Action result = node.process(getContext(sharedState, json(object()), emptyList()));

        // Then
        assertThat(result.outcome).isEqualTo(expectedOutcome);
    }


    private TreeContext getContext(JsonValue sharedState, JsonValue transientState,
                                   List<? extends Callback> callbacks) {
        return new TreeContext(sharedState, transientState, new ExternalRequestContext.Builder().build(), callbacks,
                               Optional.empty());
    }
}
