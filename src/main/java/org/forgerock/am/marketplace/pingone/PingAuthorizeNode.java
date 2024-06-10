/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */
package org.forgerock.am.marketplace.pingone;

import static java.util.Collections.singletonList;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.auth.nodes.helpers.ScriptedNodeHelper.WILDCARD;

import java.util.Date;
import java.util.List;
import java.util.Map.Entry;
import java.util.ResourceBundle;

import javax.inject.Inject;

import org.forgerock.am.marketplace.pingone.PingAuthorizeClient.FlowResult;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.StaticOutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfigChoiceValues;
import org.forgerock.util.i18n.PreferredLocales;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.sm.RequiredValueValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A node that executes "headless" DaVinci flows as described
 * <a href="https://docs.pingidentity.com/r/en-us/davinci/davinci_api_flow_launch">here</a>.
 */
@Node.Metadata(outcomeProvider = PingAuthorizeNode.OutcomeProvider.class,
    configClass = PingAuthorizeNode.Config.class,
    tags = { "marketplace", "trustnetwork" })
public class PingAuthorizeNode extends AbstractDecisionNode {

  private static final Logger logger = LoggerFactory.getLogger(PingAuthorizeNode.class);
  private String loggerPrefix = "[DaVinciNode]" + PingAuthorizePlugin.logAppender;

  private static final String BUNDLE = PingAuthorizeNode.class.getName();
  private static final String ERROR = "ERROR";

  private final Config config;
  private TNTPPingOneConfig tntpPingOneConfig;
  private final PingAuthorizeClient client;

  /**
   * Configuration for the node.
   */
  public interface Config {
    /**
     * The Configured service
     */
    @Attribute(order = 100, choiceValuesClass = TNTPPingOneConfigChoiceValues.class)
    default String tntpPingOneConfigName() {
      return TNTPPingOneConfigChoiceValues.createTNTPPingOneConfigName("Global Default");
    };

    @Attribute(order = 400, validators = {RequiredValueValidator.class})
    String flowPolicyId();

    @Attribute(order = 500)
    default List<String> inputs() {
      return singletonList(WILDCARD);
    }
  }

  @Inject
  public PingAuthorizeNode(@Assisted Config config, PingAuthorizeClient client) {
    this.config = config;
    this.client = client;
    this.tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName());
  }

  @Override
  public Action process(TreeContext context) throws NodeProcessException {
    // create the flow input based on the node state
    NodeState nodeState = context.getStateFor(this);

    JsonValue flowInput;

    if (config.inputs().contains(WILDCARD)) {
      @SuppressWarnings("unchecked")
      Entry<String, Object>[] fields = nodeState.keys().stream()
          .map(key -> field(key, nodeState.get(key)))
          .toArray(Entry[]::new);

      flowInput = json(
          object(field("nodeState",
                    object(fields))));
    } else {
      JsonValue filtered = json(object());

      config.inputs().forEach(input -> {
        if (nodeState.isDefined(input)) {
          filtered.put(input, nodeState.get(input));
        }
      });

      @SuppressWarnings("unchecked")
      Entry<String, Object>[] fields = nodeState.keys().stream()
                                                .map(key -> field(key, filtered.get(key)))
                                                .toArray(Entry[]::new);
      flowInput = json(
          object(field("nodeState",
                       object(fields))));

    }

    try {
      // execute the flow
      FlowResult result = client.executeFlowPolicy(
          tntpPingOneConfig.environmentRegion(),
          tntpPingOneConfig.environmentId(),
          config.flowPolicyId(),
          tntpPingOneConfig.dvAPIKey(),
          flowInput);

      nodeState.putShared("flowOutput", result.getResponse());

      if(result.isSuccess()) {
        return Action.goTo(TRUE_OUTCOME_ID).build();
      } else {
        return Action.goTo(FALSE_OUTCOME_ID).build();
      }
    } catch (Exception ex) {
      String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
      logger.error(loggerPrefix + "Exception occurred: ", ex);
      context.getStateFor(this).putTransient(loggerPrefix + "Exception", new Date() + ": " + ex.getMessage());
      context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", new Date() + ": " + stackTrace);
      return Action.goTo(ERROR).build();
    }

  }

  @Override
  public InputState[] getInputs() {
    return config.inputs().stream()
                 .map(input -> new InputState(input, true))
                 .toArray(InputState[]::new);
  }

  public static class OutcomeProvider implements StaticOutcomeProvider
  {
    @Override
    public List<Outcome> getOutcomes(PreferredLocales locales) {
      ResourceBundle bundle = locales.getBundleInPreferredLocale(PingAuthorizeNode.BUNDLE,
                                                                 PingAuthorizeNode.OutcomeProvider.class.getClassLoader());

      return ImmutableList.of(
          new Outcome(TRUE_OUTCOME_ID,  bundle.getString("trueOutcome")),
          new Outcome(FALSE_OUTCOME_ID, bundle.getString("falseOutcome")),
          new Outcome(ERROR, bundle.getString("errorOutcome")));
    }
  }
}
