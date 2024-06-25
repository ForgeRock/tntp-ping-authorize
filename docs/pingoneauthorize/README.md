# PingOne Authorize

The PingOne Authorize node lets administrators integrate PingOne Authorize functionality in a Journey.

## Compatibility

<table>
  <colgroup>
    <col>
    <col>
  </colgroup>
  <thead>
  <tr>
    <th>Product</th>
    <th>Compatible?</th>
  </tr>
  </thead>
  <tbody>
  <tr>
    <td><p>ForgeRock Identity Cloud</p></td>
    <td><p><span>Yes</span></p></td>
  </tr>
  <tr>
    <td><p>ForgeRock Access Management (self-managed)</p></td>
    <td><p><span>Yes</span></p></td>
  </tr>
  <tr>
    <td><p>ForgeRock Identity Platform (self-managed)</p></td>
    <td><p><span>Yes</span></p></td>
  </tr>
  </tbody>
</table>

## Inputs

This node retrieves from the journey state:
* **The AttributeMap**

Additionally, the node first looks in the journey state for the following data:
* **PingOne Authorize Policy Attribute(s):** defined within the Policy that corresponds to the active Decision Endpoint.

The node searches the journey shared state for these attributes.

## Configuration

<table>
  <thead>
  <th>Property</th>
  <th>Usage</th>
  </thead>

  <tr>
    <td>PingOne Service</td>
      <td>Service for PingOne, PingOne DaVinci API, PingOne Protect nodes, and PingOne Verify nodes
      </td>
  </tr>
  <tr>
    <td>Decision Endpoint ID</td>
    <td>The Decision Endpoint ID from the PingOne Authorize service.</td>

  </tr>
  <tr>
    <td>Attribute Map</td>
    <td>Map shared state attributes to the request parameters for the PingOne Authorize decision request.
    </td>
  </tr>
  <tr>
    <td>Statement Codes</td>
    <td>Defines the PingOne Authorize Node outcomes based off of the statements from the PingOne Authorize decision.
    </td>
  </tr>
  <tr>
    <td>Continue</td>
    <td>Use the continue toggle for a single outcome.
    </td>
  </tr>

</table>

## Outputs

This node produces no outputs.

## Outcomes

`Permit`

Satisfied the active policy's permit condition and authorized the user.

`Deny`

Satisfied the active policy's deny condition and did not authorize the user.

`Indeterminate`

Satisfied neither the active policy's permit or deny conditions.

`Error`

There was an error during the authorization process.

## Troubleshooting

If this node logs an error, review the log messages to find the reason for the error and address the issue appropriately.