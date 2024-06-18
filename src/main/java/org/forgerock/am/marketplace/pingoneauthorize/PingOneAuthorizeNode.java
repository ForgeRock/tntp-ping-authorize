/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services.
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */
package org.forgerock.am.marketplace.pingoneauthorize;

import static java.util.Collections.emptyList;
import static org.forgerock.am.marketplace.pingoneauthorize.PingOneAuthorizeNode.OutcomeProvider.CLIENT_ERROR_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingoneauthorize.PingOneAuthorizeNode.OutcomeProvider.DENY_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingoneauthorize.PingOneAuthorizeNode.OutcomeProvider.INDETERMINATE_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingoneauthorize.PingOneAuthorizeNode.OutcomeProvider.PERMIT_OUTCOME_ID;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;

import javax.inject.Inject;

import org.apache.commons.lang.exception.ExceptionUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfigChoiceValues;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneUtility;
import org.forgerock.util.i18n.PreferredLocales;
import org.forgerock.openam.core.realms.Realm;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.sm.RequiredValueValidator;
import org.jclouds.json.Json;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A node that executes "headless" DaVinci flows as described
 * <a href="https://docs.pingidentity.com/r/en-us/davinci/davinci_api_flow_launch">here</a>.
 */
@Node.Metadata(outcomeProvider = PingOneAuthorizeNode.OutcomeProvider.class,
               configClass = PingOneAuthorizeNode.Config.class,
               tags = {"marketplace", "trustnetwork"})
public class PingOneAuthorizeNode extends SingleOutcomeNode {

    private final Realm realm;

    private static final Logger logger = LoggerFactory.getLogger(PingOneAuthorizeNode.class);
    private String loggerPrefix = "[PingAuthorizeNode]" + PingOneAuthorizePlugin.logAppender;

    private static final String BUNDLE = PingOneAuthorizeNode.class.getName();
    private static final String STATEMENTS = "statements";
    private static final String PERMIT = "PERMIT";
    private static final String DENY = "DENY";
    private static final String INDETERMINATE = "INDETERMINATE";

    private final Config config;
    private TNTPPingOneConfig tntpPingOneConfig;
    private final PingOneAuthorizeClient client;

    public enum FlowType { PAZ, P1AZ }

    public String getFlowType(FlowType flowType) {
        if (flowType == FlowType.PAZ) {return "PAZ";}
        else return "P1AZ";
    }

    public int getUseContinue() {
        if(config.useContinue()) {
            return 1;
        } else {
            return 0;
        }
    }

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The Configured service
         */

        @Attribute(order = 100)
        default FlowType flowType() {
            return FlowType.P1AZ;
        }

        @Attribute(order = 200)
        default String endpointUrl() {
            return "";
        }

        @Attribute(order = 400, choiceValuesClass = TNTPPingOneConfigChoiceValues.class)
        default String tntpPingOneConfigName() {
            return TNTPPingOneConfigChoiceValues.createTNTPPingOneConfigName("Global Default");
        }

        @Attribute(order = 500, validators = {RequiredValueValidator.class})
        String decisionEndpointID();

        @Attribute(order = 600)
        List<String> attributeMap();

        @Attribute(order = 700)
        default List<String> statements() {
            return emptyList();
        }

        @Attribute(order = 800)
        default boolean useContinue() {
            return false;
        }
    }

    @Inject
    public PingOneAuthorizeNode(@Assisted Config config, @Assisted Realm realm, PingOneAuthorizeClient client) {
        this.config = config;
        this.realm = realm;
        this.client = client;
        this.tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName());
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        // create the flow input based on the node state
        NodeState nodeState = context.getStateFor(this);

        // Loops through the string list `attributeMap`
        // Places the key (from attributeMap) and value (from nodeState) into the `retrievedAttributes` HashMap.
        Map<String, String> parameters = new HashMap<>();
        for (String key : config.attributeMap()) {
            parameters.put(key, String.valueOf((nodeState.get(key))));
        }

        logger.error("\n" + "nodeState contents: {}", nodeState);
        logger.error("\n" + "attributeMap contents: {}", config.attributeMap());
        logger.error("\n" + "attributeMap: {}", config.attributeMap());
        logger.error("\n" + "parameters: {}", parameters);
        logger.error("\n" + "JSON parameters: {}", JsonValue.json(parameters));

        try {
            TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
            // Retrieve access token
            AccessToken accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
            // Create and send API call
            JsonValue response = client.evaluateDecisionRequest(
                    accessToken,
                    tntpPingOneConfig,
                    config.decisionEndpointID(),
                    JsonValue.json(parameters));

            logger.error(response.toString());

            // Retrieve API response
            nodeState.putTransient("decision", response);

            String statement = response.get(STATEMENTS).get(0).toString();
            logger.error(statement);

            if (config.statements().contains(statement)) {
                logger.error("Statement found in configured statements");
                return Action.goTo(statement).build();
            }

            String decision = response.get("decision").toString();

            logger.error(decision);

            switch (decision) {
                case PERMIT:
                    return Action.goTo(PERMIT_OUTCOME_ID).build();
                case DENY:
                    return Action.goTo(DENY_OUTCOME_ID).build();
                case INDETERMINATE:
                    return Action.goTo(INDETERMINATE_OUTCOME_ID).build();
                default:
                    return Action.goTo(CLIENT_ERROR_OUTCOME_ID).build();
            }

        } catch (Exception ex) {
            String stackTrace = ExceptionUtils.getStackTrace(ex);
            logger.error(loggerPrefix + "Exception occurred: ", ex);
            context.getStateFor(this).putTransient(loggerPrefix + "Exception", new Date() + ": " + ex.getMessage());
            context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", new Date() + ": " + stackTrace);
            return Action.goTo(CLIENT_ERROR_OUTCOME_ID).build();
        }
    }

    public static class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {

        static final String PERMIT_OUTCOME_ID = "permit";
        static final String DENY_OUTCOME_ID = "deny";
        static final String INDETERMINATE_OUTCOME_ID = "indeterminate";
        static final String CONTINUE_OUTCOME_ID = "continue";
        static final String CLIENT_ERROR_OUTCOME_ID = "clientError";

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) throws NodeProcessException {

            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, PingOneAuthorizeNode.OutcomeProvider.class.getClassLoader());

            ArrayList<Outcome> outcomes = new ArrayList<>();

            String useContinue = nodeAttributes.get("useContinue").toString();
            if (useContinue.equals("true")) {
                outcomes.add(new Outcome(CONTINUE_OUTCOME_ID, bundle.getString(CONTINUE_OUTCOME_ID)));
            } else {
                outcomes.add(new Outcome(PERMIT_OUTCOME_ID, bundle.getString(PERMIT_OUTCOME_ID)));
                outcomes.add(new Outcome(DENY_OUTCOME_ID, bundle.getString(DENY_OUTCOME_ID)));
                outcomes.add(new Outcome(INDETERMINATE_OUTCOME_ID, bundle.getString(INDETERMINATE_OUTCOME_ID)));
                if (nodeAttributes.isNotNull()) {
                    // nodeAttributes is null when the node is created
                    nodeAttributes.get(STATEMENTS).required()
                                  .asList(String.class)
                                  .stream()
                                  .map(outcome -> new Outcome(outcome, outcome))
                                  .forEach(outcomes::add);
                }
            }
            outcomes.add(new Outcome(CLIENT_ERROR_OUTCOME_ID, bundle.getString(CLIENT_ERROR_OUTCOME_ID)));

            return outcomes;
        }
    }
}