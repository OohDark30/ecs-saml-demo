# ecs-saml-demo
----------------------------------------------------------------------------------------------
ecs-saml-demo is a PYTHON application that demonstrates using DELL EMC's 
ECS Secure Token Service (STS) to generate temporary credentials using a SAML Assertion

ecs-saml-demo will do the following:
1. Prompt for a user's AD credentials.  
2. Connect to a Federation identity provider endpoint which will generate an HTML authentication prompt
3. Parse the HTML authentication form returned by the identity provider and plugin in the gathered credentials 
and submit the form
4. The response from submitting the form will be parsed for a SAML assertion if generated
5. The SAML assertion is then encoded and used to make a call to the configured DELL EMC's ECS STS API
6. If successful parse the response and use the temporary credentials to perform test S3 operations

For more information, please see the [wiki](https://github.com/OohDark30/ecs-saml-assertion-demo/wiki)


