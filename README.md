# ecs-saml-demo
----------------------------------------------------------------------------------------------
ecs-saml-demo is a PYTHON application that demonstrates using DELL EMC's 
ECS Secure Token Service (STS) to generate temporary credentials using a SAML Assertion

ecs-saml-demo will do the following:
1. Prompt for a user's credentials.  
2. Connect to a Federation identity provider endpoint which will generate an HTML authentication prompt
3. Parse the HTML authentication form returned by the identity provider and plugin in the gathered credentials 
and submit the form
   - NOTE: `Please Note this script will search the login form presented by the SSO endpoint looking for credential fields to populate with the 
         entered credentials. Every IdPs login forms are different so make sure you understand the HTML form being presented by your SSO
         Endpoint and adjust the script accordingly`
   - Note: `This goes for the Action when we re-submit the form.  Make sure your using the correct URL!`
4. The response from submitting the form will be parsed for a SAML assertion if generated
5. The SAML assertion is then parsed to search to see if it contains the "https://aws.amazon.com/SAML/Attributes/Role" attribute and if it does it is parsed for a list of roles
6. The user is then presented with a list of roles that they want to use to make the AssumeRoleWithSAML call to the ECS STS API
6. The SAML assertion is then encoded and used to make a call to the configured DELL EMC's ECS STS API
7. If successful parse the response and use the temporary credentials to perform test S3 operations

For more information, please see the [wiki](https://github.com/OohDark30/ecs-saml-demo/wiki)


