<!--
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. Ping Identity Corporation only offers such software or services to legal entities who have entered into a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
-->

# PingOne Authorize and PingAuthorize Nodes

The PingOne Authorize Node sends a decision request to a specified decision endpoint, while the PingAuthorize Node authorizes a client through the Policy Decision Service. These authorizations include:

* [Policy Decision Authorization](https://apidocs.pingidentity.com/pingone/platform/v1/api/#post-evaluate-a-decision-request)
* [Individual Requests](https://apidocs.pingidentity.com/pingauthorize/authorization-policy-decision/v1/api/guide/#post-authorize-client-with-individual-decision:~:text=leave%20it%20empty.-,Authorize%20client%20with%20individual%20decision,-%7B%7BapiPath%7D%7D/governance%2Dengine)

Identity Cloud provides the following artifacts to enable the PingOne Authorize and PingAuthorize Nodes:

* [PingOne service](https://github.com/ForgeRock/tntp-ping-service/blob/main/README.md)
* [PingOne Authorize node](https://github.com/ForgeRock/tntp-ping-authorize/blob/main/docs/pingoneauthorize/README.md)
* [PingAuthorize node](https://github.com/ForgeRock/tntp-ping-authorize/blob/main/docs/pingauthorize/README.md)

You must set up the following before using the PingOne Authorize and PingAuthorize nodes:

* [Create an authorize policy](https://docs.pingidentity.com/r/en-us/pingone/p1az_policies)
* [Create a worker application](https://docs.pingidentity.com/r/en-us/pingone/p1_add_app_worker)
    * Requires [Identity Data Admin](https://apidocs.pingidentity.com/pingone/platform/v1/api/#roles) role
* [PingOne service](https://github.com/ForgeRock/tntp-ping-service/tree/cloudprep?tab=readme-ov-file#ping-one-service)
