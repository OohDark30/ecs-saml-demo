# ecs-saml-demo configuration
----------------------------------------------------------------------------------------------
ecs-saml-demo is a PYTHON application that demonstrates using DELL EMC's
ECS Secure Token Service (STS) to generate temporary credentials using a SAML Assertion

The demo uses a configuration file that allows the user to pre-configure:

the ECS where the STS API calls will be made

We've provided a sample configuration file:

- ecs_saml_demo_config.sample: Change file suffix from .sample to .json and configure as needed
  This contains the tool configuration for ECS and database connection, logging level, etc. Here
  is the sample configuration:
  
  BASE:
  logging_level - The default is "info" but it can be set to "debug" to generate a LOT of details
  datastore - This is a placeholder for future datastores.  At the moment it's set to "influx"
  
  ECS_CONNECTION:
  protocol - Should be set to "https"
  host - This is the IP address of FQDN of an ECS node
  port - This is always "4443" which is the ECS Management API port
  user - This is the user id of an ECS Management User 
  password - This is the password for the ECS Management User

  SAML_IDP:
  idp_sso_url = This is the URL of the SSO for the Identity Provider

  AWS_CONFIGURATION
  region - This is the AWS Region
  output - This is the output format for AWS CLI commands