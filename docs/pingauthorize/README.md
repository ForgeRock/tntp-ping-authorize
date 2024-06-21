# PingAuthorize

The PingAuthorize node lets administrators integrate PingAuthorize functionality in a Journey.

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
* **PingAuthorize Policy Attribute(s):** defined within the Policy that corresponds to the active Decision Endpoint.

The node searches the journey shared state for these attributes.

## Configuration

<table>
  <thead>
    <th>Property</th>
    <th>Usage</th>
  </thead>
  <tbody>
    <tr>
      <td>Endpoint Url</td>
      <td>PingAuthorize decision endpoint url.
      </td>
    </tr>
  <tr>
    <td>Access Token</td>
    <td><br>
</td>
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

`Success`

All checks passed.

`Fail`

One of the checks failed.

`Error`

There was an error during the authorization process.

## Troubleshooting

If this node logs an error, review the log messages to find the reason for the error and address the issue
appropriately.
