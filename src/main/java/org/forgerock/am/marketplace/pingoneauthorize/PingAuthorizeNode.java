/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services.
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */
package org.forgerock.am.marketplace.pingoneauthorize;

import com.google.inject.assistedinject.Assisted;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.ResourceBundle;

import static java.util.Collections.emptyList;
import static org.forgerock.am.marketplace.pingoneauthorize.PingOneAuthorizeNode.OutcomeProvider.CLIENT_ERROR_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingoneauthorize.PingOneAuthorizeNode.OutcomeProvider.DENY_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingoneauthorize.PingOneAuthorizeNode.OutcomeProvider.INDETERMINATE_OUTCOME_ID;
import static org.forgerock.am.marketplace.pingoneauthorize.PingOneAuthorizeNode.OutcomeProvider.PERMIT_OUTCOME_ID;

/**
 * The PingAuthorize node lets administrators integrate PingAuthorize functionality in a Journey.
 */
@Node.Metadata(outcomeProvider = PingAuthorizeNode.OutcomeProvider.class,
               configClass = PingAuthorizeNode.Config.class,
               tags = {"marketplace", "trustnetwork"})
public class PingAuthorizeNode extends SingleOutcomeNode {

    private static final Logger logger = LoggerFactory.getLogger(PingAuthorizeNode.class);
    private final String loggerPrefix = "[PingAuthorizeNode]" + PingOneAuthorizePlugin.LOG_APPENDER;

    private static final String BUNDLE = PingAuthorizeNode.class.getName();

    // Attribute keys
    private static final String STATEMENTCODESATTR = "statementCodes";
    private static final String USECONTINUEATTR = "useContinue";
    private static final String STATEMENT_KEY = "statements";

    // Outcomes
    private static final String PERMIT = "PERMIT";
    private static final String DENY = "DENY";
    private static final String INDETERMINATE = "INDETERMINATE";

    private final Config config;
    private final AuthorizeClient client;

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
         * A shared state attribute containing the Endpoint URL.
         *
         * @return The Endpoint URL shared state attribute.
         */
        @Attribute(order = 100, requiredValue = true)
        String endpointUrl();

        /**
         * A shared state attribute containing the Access Token.
         *
         * @return The Access Token shared state attribute.
         */
        @Attribute(order = 200, requiredValue = true)
        String accessTokenAttribute();

        /**
         * The list of Policy attributes defined within the PingOne Authorize Trust Framework.
         *
         * @return List of Policy attributes as a List of Strings.
         */
        @Attribute(order = 300)
        List<String> attributeMap();

        /**
         * The list of Statement codes defined within the PingOne Authorize Policy.
         *
         * @return List of Statement codes if they are provided; otherwise, it returns an empty list.
         */
        @Attribute(order = 400)
        default List<String> statementCodes() {
            return emptyList();
        }

        /**
         * Sets the Node to render a single outcome.
         *
         * @return true if the node is set a single outcome, otherwise false.
         */
        @Attribute(order = 500)
        default boolean useContinue() {
            return false;
        }
    }

    /**
     * The PingAuthorize node constructor.
     *
     * @param config               the node configuration.
     * @param client               the {@link AuthorizeClient} instance.
     */
    @Inject
    public PingAuthorizeNode(@Assisted Config config, AuthorizeClient client) {
        this.config = config;
        this.client = client;
    }

    @Override
    public Action process(TreeContext context) {
        // create the flow input based on the node state
        NodeState nodeState = context.getStateFor(this);

        String accessToken = nodeState.get(config.accessTokenAttribute()).asString();

        // Loops through the string list `attributeMap`
        // Places the key (from attributeMap) and value (from nodeState) into the `retrievedAttributes` HashMap.
        JsonValue parameters = new JsonValue(new HashMap<String, String>(1));
        for (String key : config.attributeMap()) {
            parameters.put(key, nodeState.get(key));;
        }

        try {
            // Create and send API call
            JsonValue response = client.pingAZEvaluateDecisionRequest(
                    config.endpointUrl(),
                    accessToken,
                    parameters);

            // Retrieve API response
            nodeState.putTransient("decision", response);

            // Retrieves the "code" value from the "statements" object inside the API response body
            String statementCode = response.get(STATEMENT_KEY).get(0).get("code").asString();

            if (config.statementCodes().contains(statementCode)) {
                return Action.goTo(statementCode).build();
            }

            // The API response's "decision" value will determine which outcome is executed
            String decision = response.get("decision").asString();
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

    @Override
    public InputState[] getInputs() {

        List<InputState> inputs = new ArrayList<>();

        inputs.add(new InputState(config.accessTokenAttribute(), true));

        config.attributeMap().forEach(
            (v) -> inputs.add(new InputState(v, false)));

        return inputs.toArray(new InputState[]{});
    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[]{
            new OutputState("decision")
        };
    }

    public static class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {

        static final String PERMIT_OUTCOME_ID = "permit";
        static final String DENY_OUTCOME_ID = "deny";
        static final String INDETERMINATE_OUTCOME_ID = "indeterminate";
        static final String CONTINUE_OUTCOME_ID = "continue";
        static final String CLIENT_ERROR_OUTCOME_ID = "clientError";

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) throws NodeProcessException {

            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, PingAuthorizeNode.OutcomeProvider.class.getClassLoader());

            ArrayList<Outcome> outcomes = new ArrayList<>();

            // Retrieves the current state of the continue button
            String useContinue = nodeAttributes.get(USECONTINUEATTR).toString();

            // Do not render other outcomes if button = "true"
            if (useContinue.contains("true")) {
                outcomes.add(new Outcome(CONTINUE_OUTCOME_ID, bundle.getString(CONTINUE_OUTCOME_ID)));
            } else {
                outcomes.add(new Outcome(PERMIT_OUTCOME_ID, bundle.getString(PERMIT_OUTCOME_ID)));
                outcomes.add(new Outcome(DENY_OUTCOME_ID, bundle.getString(DENY_OUTCOME_ID)));
                outcomes.add(new Outcome(INDETERMINATE_OUTCOME_ID, bundle.getString(INDETERMINATE_OUTCOME_ID)));
                if (nodeAttributes.isNotNull()) {
                    // nodeAttributes is null when the node is created
                    nodeAttributes.get(STATEMENTCODESATTR).required()
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
