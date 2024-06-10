<!--
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. Ping Identity Corporation only offers such software or services to legal entities who have entered into a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
-->

# PingOne

The PingOne node establishes trust between PingOne and Identity Cloud by leveraging a federated connection.

Identity Cloud provides the following artifacts to enable the PingOne node:

* [PingOne service](https://github.com/ForgeRock/tntp-ping-service/tree/cloudprep?tab=readme-ov-file#ping-one-service)
* [PingOne node](https://github.com/ForgeRock/tntp-pingone-davinci/tree/cloudprep/docs/pingone#pingone-node)

You must set up the following before using the PingOne node:

* [A PingOne OIDC Application configured to your Identity Cloud instance](https://github.com/ForgeRock/tntp-pingone-davinci/tree/cloudprep/docs/pingone#a-pingone-oidc-application-configured-to-your-identity-cloud-instance)
* [PingOne service](https://github.com/ForgeRock/tntp-ping-service/tree/cloudprep?tab=readme-ov-file#ping-one-service)

For more information on this node, refer to the PingOne node

## PingOne setup
You must set up the following before using the PingOne node:

* [A PingOne OIDC Application configured to your Identity Cloud instance](https://github.com/ForgeRock/tntp-pingone-davinci/tree/cloudprep/docs/pingone#a-pingone-oidc-application-configured-to-your-identity-cloud-instance)
* [PingOne service](https://github.com/ForgeRock/tntp-ping-service/tree/cloudprep?tab=readme-ov-file#ping-one-service)

### A PingOne OIDC Application configured to your Identity Cloud instance
***
From the PingOne environment, use the Applications page to add an application to be used by Identity Cloud to connect to PingOne.

1. Go to **Applications** -> **Applications**.
2. Click the **+** icon.
3. Create the application profile by entering the following:
  * **Application name**: Identity Cloud Federation
  * **Description** (optional): Enables federation from Identity Cloud to PingOne
4. Choose the OIDC Web App for Application Type.
5. Click Save
6. Once the Application is created, click the **Configuration** tab and then click the **Pencil** icon to edit the Application.
7. Under **PKCE Enforcement** click the drop-down and select **S256_REQUIRED**.
8. Under **Token Endpoint Authentication Method** click the drop-down and select **Client Secret Post**.
9. Next, click the **Require Pushed Authorization Request** checkbox.
10. Finally, enter the **Redirect URIs** of the ForgeRock AM instance.
11. Click **Save** and enable the **Application** by clicking on the toggle button.

## PingOne node
The PingOne node establishes trust between PingOne and Identity Cloud by leveraging a federated connection.

### Compatibility
***

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
<td><p><span><i>✓</i></span></p></td>
</tr>
<tr>
<td><p>ForgeRock Access Management (self-managed)</p></td>
<td><p><span><i>✓</i></span></p></td>
</tr>
<tr>
<td><p>ForgeRock Identity Platform (self-managed)</p></td>
<td><p><span class="icon"><i class="fa fa-check" title="yes">✓</i></span></p></td>
</tr>
</tbody>
</table>

### Inputs
***
Any data in the node state that needs to be sent to PingOne.

### Dependencies
***
To use this node, you must configure the PingOne service.


### Configuration
***
The configurable properties for this node are:


<table><colgroup><col><col></colgroup><thead>
						<tr>
							<th class="entry colsep-1 rowsep-1" id="jzf1692634635960__table_y2d_vml_nyb__entry__1">Property</th>
							<th class="entry colsep-1 rowsep-1" id="jzf1692634635960__table_y2d_vml_nyb__entry__2">Usage</th>
						</tr>
					</thead><tbody class="tbody">
						<tr class="row">
							<td class="entry colsep-1 rowsep-1" headers="jzf1692634635960__table_y2d_vml_nyb__entry__1">
								<p class="p">PingOne Service</p>
							</td>
							<td class="entry colsep-1 rowsep-1" headers="jzf1692634635960__table_y2d_vml_nyb__entry__2">
                The PingOne Service used for this Verify Node</td>
						</tr>



<tr>
    <td>
        ACR Value
    </td>
    <td>
        An optional field which can be used to trigger a specific PingOne Application policy
    </td>
</tr>
<tr>
    <td>
       Inputs
    </td>
    <td>
      A multi-value field which can used to select specific Node State attributes to include the Federation request to PingOne.  By default the Wildcard * value will include the entire Journey Node State in the federation request to PingOne
    </td>
</tr>

</tbody></table>


### Outputs
***
Any claims returned by PingOne during federation will be stored in Node State.

### Outcomes
***
`Account exists`

If the account returned by PingOne during federation matches an existing account and is linked to the account in Identity Cloud.

`Account exists, no link`

If the account returned by PingOne during federation exists in Identity Cloud but it is not yet linked to the existing account in Identity Cloud.

`No account exists`

If the account returned by PingOne during federation does not exists in Identity Cloud.

`No ID Match`

The PingOne pseudoanonymized userId provided (stored on the user or in SharedState), does not match any ID in PingOne

`Error`

An error occurred causing the request to fail. Check the response code, response body, or logs to see more details of the error.
### Troubleshooting
***
If this node logs an error, review the log messages to find the reason for the error and address the issue appropriately.

### Examples
***
This example journey highlights the use of the PingOne node

![ScreenShot](./example.png)
