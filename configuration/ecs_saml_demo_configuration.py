"""
DELL EMC ECS SAML Assertion Demo.
"""
import logging
import os
import json
import numbers

# Constants
BASE_CONFIG = 'BASE'                                          # Base Configuration Section
ECS_CONNECTION_CONFIG = 'ECS_CONNECTION'                      # ECS Connection Configuration Section
AWS_CONNECTION_CONFIG = 'AWS_CONFIGURATION'                   # AWS Configuration Section
SAML_IDP_CONFIGURATION = 'SAML_IDP'                           # SAML Configuration Section


class InvalidConfigurationException(Exception):
    pass


class ECSSAMLConfiguration(object):
    def __init__(self, config, tempdir):

        if config is None:
            raise InvalidConfigurationException("No file path to the ECS SAML Demo Module configuration provided")

        if not os.path.exists(config):
            raise InvalidConfigurationException("The ECS SAML Demo Module configuration "
                                                "file path does not exist: " + config)
        if tempdir is None:
            raise InvalidConfigurationException("No path for temporary file storage provided")

        # Store temp file storage path to the configuration object
        self.tempfilepath = tempdir

        # Attempt to open configuration file
        try:
            with open(config, 'r') as f:
                parser = json.load(f)
        except Exception as e:
            raise InvalidConfigurationException("The following unexpected exception occurred in the "
                                                "ECS SAML Demo Module attempting to parse "
                                                "the configuration file: " + e.message)

        # We parsed the configuration file now lets grab values
        self.ecsconnections = parser[ECS_CONNECTION_CONFIG]

        # Set logging level
        logging_level_raw = parser[BASE_CONFIG]['logging_level']
        self.logging_level = logging.getLevelName(logging_level_raw.upper())

        # Grab AWS settings and validate
        self.aws_region = parser[AWS_CONNECTION_CONFIG]['region']
        self.aws_output = parser[AWS_CONNECTION_CONFIG]['output']

        # Grab SAML IDP Settings
        self.saml_idp_url = parser[SAML_IDP_CONFIGURATION]['idp_sso_url']

        # Validate logging level
        if logging_level_raw not in ['debug', 'info', 'warning', 'error']:
            raise InvalidConfigurationException(
                "Logging level can be only one of ['debug', 'info', 'warning', 'error']")

        # Iterate through all configured ECS connections and validate connection info
        for ecsconnection in self.ecsconnections:
            # Validate ECS Connections values
            if not ecsconnection['protocol']:
                raise InvalidConfigurationException("The ECS Management protocol is not "
                                                    "configured in the module configuration")
            if not ecsconnection['host']:
                raise InvalidConfigurationException("The ECS Management Host is not configured in the module configuration")
            if not ecsconnection['port']:
                raise InvalidConfigurationException("The ECS Management port is not configured in the module configuration")
            if not ecsconnection['user']:
                raise InvalidConfigurationException("The ECS Management User is not configured in the module configuration")
            if not ecsconnection['password']:
                raise InvalidConfigurationException("The ECS Management Users password is not configured "
                                                    "in the module configuration")
            # Validate API query parameters
            if not ecsconnection['dataType']:
                ecsconnection['dataType'] = "default"

            if not ecsconnection['category']:
                ecsconnection['category'] = "default"

            if not ecsconnection['connectTimeout']:
                ecsconnection['connectTimeout'] = "15"

            if not ecsconnection['readTimeout']:
                ecsconnection['readTimeout'] = "60"
