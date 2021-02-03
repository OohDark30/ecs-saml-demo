"""
""
"""
import base64
import urllib

import requests
from bs4 import BeautifulSoup

from configuration.ecs_saml_demo_configuration import ECSSAMLConfiguration
from logger import ecs_logger
from ecs.ecs import ECSAuthentication
from ecs.ecs import ECSManagementAPI
from ecs.ecs import ECSUtility
import errno
import datetime
import getpass
import os
import traceback
import signal
import time
import logging
import xml.etree.ElementTree as ET
import re
import xml.etree.ElementTree as ET

# Constants
MODULE_NAME = "ECS_Data_Collection_Module"  # Module Name
INTERVAL = 30  # In seconds
CONFIG_FILE = 'ecs_saml_demo_config.json'  # Default Configuration File

# Globals
_configuration = None
_ecsManagementNode = None
_ecsManagementUser = None
_ecsManagementUserPassword = None
_logger = None
_ecsAuthentication = list()
_influxClient = None
_ecsVDCLookup = None
_ecsManagmentAPI = list()

"""
Class to listen for signal termination for controlled shutdown
"""


class ECSDataCollectionShutdown:
    kill_now = False

    def __init__(self):
        signal.signal(signal.SIGINT, self.controlled_shutdown)
        signal.signal(signal.SIGTERM, self.controlled_shutdown)

    def controlled_shutdown(self, signum, frame):
        self.kill_now = True


class ECSDataCollection():
    def __init__(self, method, logger, ecsmanagmentapi, tempdir, saml_assertion):
        self.method = method
        self.logger = logger
        self.ecsmanagmentapi = ecsmanagmentapi
        self.tempdir = tempdir
        self.assertion = saml_assertion

        logger.info(MODULE_NAME + '::ECSDataCollection()::init method of class called')

        try:
            self.logger.info(MODULE_NAME + '::ECSDataCollection()::Starting method: ' + self.method)

            if self.method == 'ecs_assume_role_saml':
                ecs_assume_role_saml(self.logger, self.ecsmanagmentapi, self.tempdir, self.assertion)
            else:
                self.logger.info(MODULE_NAME + '::ECSDataCollection()::Requested method ' +
                                 self.method + ' is not supported.')
        except Exception as e:
            _logger.error(MODULE_NAME + 'ECSDataCollection::run()::The following unexpected '
                                        'exception occured: ' + str(e) + "\n" + traceback.format_exc())


class ECSSAMLAssertion:
    def __init__(self, assertion):
        self.saml_assertion = assertion
        self.roles = []
        self.providers = []

    def addRole(self, role):
        self.roles.append(role)

    def addProvider(self, provider):
        self.roles.providers(provider)


def ecs_check_for_integer(var_to_check):
    global _logger

    try:
        # Try and convert variable to integer
        int(var_to_check)
        return True
    except ValueError:
        return False


def ecs_delete_file(file_to_delete):
    global _logger

    try:
        # Load and validate module configuration
        os.remove(file_to_delete)

        _logger.debug(MODULE_NAME + '::ecs_delete_file()::Successfully deleted file ' + file_to_delete + '.')
    except OSError as e:
        if e.errno != errno.ENOENT:
            _logger.error(MODULE_NAME + '::ecs_delete_file()::The following unexpected '
                                        'exception occured: ' + str(e) + "\n" + traceback.format_exc())


def ecs_config(config, temp_dir):
    global _configuration
    global _logger
    global _ecsAuthentication

    try:
        # Load and validate module configuration
        _configuration = ECSSAMLConfiguration(config, temp_dir)

        # Grab loggers and log status
        _logger = ecs_logger.get_logger(__name__, _configuration.logging_level)
        _logger.info(MODULE_NAME + '::ecs_config()::We have configured logging level to: '
                     + logging.getLevelName(str(_configuration.logging_level)))
        _logger.info(MODULE_NAME + '::ecs_config()::Configuring ECS SAML Demo Module complete.')
        return _logger
    except Exception as e:
        _logger.error(MODULE_NAME + '::ecs_config()::The following unexpected '
                                    'exception occured: ' + str(e) + "\n" + traceback.format_exc())


def ecs_assume_role_saml(logger, ecsmanagmentapi, tempdir, assertion):
    try:
        # Perform API call against each configured ECS
        for ecsconnection in ecsmanagmentapi:

            # for each role / provider combination call the AssumeRoleWithSAML STS API
            i = 0
            assertion_saml = assertion.saml_assertion
            while i < len(assertion.roles):
                assume_role_with_saml_data = ecsconnection.assume_role_with_saml(assertion_saml,
                                                                                 assertion.roles[i],
                                                                                 assertion.providers[i], tempdir)
                if assume_role_with_saml_data is None:
                    # If we had an issue just log the error and keep going to the next bucket
                    logger.info(MODULE_NAME + '::ecs_assume_role_saml()::Unable to retrieve temporary credentials '
                                              'for role ' + assertion.roles[i] + ' and provider ' +
                                assertion.providers[i])
                else:
                    # We have a response from the AssumeRoleWithSAML API call
                    # Let's parse it
                    try:
                        tree = ET.parse(assume_role_with_saml_data)
                        sts_results_data = tree.getroot()

                        # Grab temporary credentials
                        aws_access_key_id = sts_results_data[1][2][0].text
                        credentials_expiration = sts_results_data[1][2][1].text
                        aws_secret_access_key = sts_results_data[1][2][2].text
                        aws_session_token = sts_results_data[1][2][3].text

                        # Print to screen
                        print("#################### Temporary Credentials Returned from ECS STS API Call ###############################:")
                        print('AWS_ACCESS_KEY_ID: {}'.format(aws_access_key_id))
                        print('AWS_SECRET_ACCESS_KEY: {}'.format(aws_secret_access_key))
                        print('AWS_SESSION_TOKEN: {}'.format(aws_session_token))
                        print("#########################################################################################################:")


                        # If we had an issue just log the error and keep going to the next bucket
                        logger.info(MODULE_NAME + '::ecs_assume_role_saml()::Retrieved the following temporary'
                                                  ' credentials for role ' + assertion.roles[i] + ' and provider: ' +
                                    assertion.providers[i])
                        logger.info(MODULE_NAME + '::ecs_assume_role_saml()::aws_access_key_id: ' + aws_access_key_id)
                        logger.info(MODULE_NAME + '::ecs_assume_role_saml()::aws_secret_access_key: ' + aws_secret_access_key)
                        logger.info(MODULE_NAME + '::ecs_assume_role_saml()::aws_session_token: ' + aws_session_token)

                        _logger.debug(
                            MODULE_NAME + '::ecs_assume_role_saml::Deleting temporary '
                                          'xml file: ' + assume_role_with_saml_data)
                    except Exception as ex:
                        _logger.error(
                            MODULE_NAME + '::ecs_assume_role_saml()::The following unexpected '
                                          'exception occurred: ' + str(
                                ex) + "\n" + traceback.format_exc())

                i += 1
    except Exception as e:
        _logger.error(MODULE_NAME + '::ecs_assume_role_saml()::The following unexpected '
                                    'exception occured: ' + str(e) + "\n" + traceback.format_exc())


def ecs_authenticate():
    global _ecsAuthentication
    global _configuration
    global _logger
    global _ecsManagmentAPI
    connected = True

    try:
        # Wait till configuration is set
        while not _configuration:
            time.sleep(1)

        # Iterate over all ECS Connections configured and attempt tp Authenticate to ECS
        for ecsconnection in _configuration.ecsconnections:

            # Attempt to authenticate
            auth = ECSAuthentication(ecsconnection['protocol'], ecsconnection['host'], ecsconnection['user'],
                                     ecsconnection['password'], ecsconnection['port'], _logger)

            auth.connect()

            # Check to see if we have a token returned
            if auth.token is None:
                _logger.error(MODULE_NAME + '::ecs_init()::Unable to authenticate to ECS as configured.  '
                                            'Please validate and try again.')
                connected = False
                break
            else:
                _ecsAuthentication.append(auth)

                # Instantiate ECS Management API object, add it to our list, and validate that we are authenticated
                _ecsManagmentAPI.append(ECSManagementAPI(auth, ecsconnection['connectTimeout'],
                                                         ecsconnection['readTimeout'], _logger))
                if not _ecsAuthentication:
                    _logger.info(MODULE_NAME + '::ecs_authenticate()::ECS SAML Assertion '
                                               'Module is not ready.  Please check logs.')
                    connected = False
                    break

        return connected

    except Exception as e:
        _logger.error(MODULE_NAME + '::ecs_init()::Cannot initialize plugin. Cause: '
                      + str(e) + "\n" + traceback.format_exc())
        connected = False


def ecs_data_collection():
    global _influxClient
    global _ecsAuthentication
    global _logger
    global _ecsManagmentAPI

    try:
        # Wait till configuration is set
        while not _configuration:
            time.sleep(1)

        # Now lets spin up a thread for each API call with it's own custom polling interval by iterating
        # through our module configuration
        for i, j in _configuration.modules_intervals.items():
            method = str(i)
            interval = str(j)
            t = ECSDataCollection(method, _influxClient, _logger, _ecsManagmentAPI, interval,
                                  _configuration.tempfilepath)
            t.start()

    except Exception as e:
        _logger.error(MODULE_NAME + '::ecs_data_collection()::A failure ocurred during data collection. Cause: '
                      + str(e) + "\n" + traceback.format_exc())


def ecs_ido_sso_login(username, password):
    global _logger
    global _configuration

    # Initiate session handler
    session = requests.Session()

    # Programmatically get the SAML assertion
    # Opens the initial IdP url and follows all of the HTTP302 redirects, and
    # gets the resulting login page
    sslverification = False
    formresponse = session.get(_configuration.saml_idp_url, verify=sslverification)

    # Capture the idpauthformsubmiturl, which is the final url after all the 302s
    idpauthformsubmiturl = formresponse.url

    # Parse the response and extract all the necessary values
    # in order to build a dictionary of all of the form values the IdP expects
    formsoup = BeautifulSoup(formresponse.text, features="lxml")
    payload = {}

    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name', '')
        value = inputtag.get('value', '')
        if "user" in name.lower():
            # Make an educated guess that this is the right field for the username
            payload[name] = username
        elif "email" in name.lower():
            # Some IdPs also label the username field as 'email'
            payload[name] = username
        elif "pass" in name.lower():
            # Make an educated guess that this is the right field for the password
            payload[name] = password
        else:
            # Simply populate the parameter with the existing value (picks up hidden fields in the login form)
            payload[name] = value

    # Debug the parameter payload if needed
    # Use with caution since this will print sensitive output to the screen
    # print payload

    # Some IdPs don't explicitly set a form action, but if one is set we should
    # build the idpauthformsubmiturl by combining the scheme and hostname
    # from the entry url with the form action target
    # If the action tag doesn't exist, we just stick with the
    # idpauthformsubmiturl above
    for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
        action = inputtag.get('action')
        loginid = inputtag.get('id')
        if action and loginid == "loginForm":
            parsedurl = urllib.parse.urlparse(_configuration.saml_idp_url)
            idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

    # Performs the submission of the IdP login form with the above post data
    response = session.post(
        idpauthformsubmiturl, data=payload, verify=sslverification)

    # Debug the response if needed
    # print (response.text)

    # Overwrite and delete the credential variables, just for safety
    username = '##############################################'
    password = '##############################################'
    del username
    del password

    # Decode the response and extract the SAML assertion
    soup = BeautifulSoup(response.text, features="lxml")
    assertion = ''
    urlEncodedAssertion = ''

    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if (inputtag.get('name') == 'SAMLResponse'):
            # print(inputtag.get('value'))
            assertion = inputtag.get('value')

    # Better error handling is required for production use.
    if assertion == '':
        _logger.error(MODULE_NAME + '::ecs_ido_sso_login()::The Identity Provider '
                                    'did not return a valid SAML Assertion .')
        return None

    # Debug only
    print("#################### BASE64 SAML Assertion ###############################:")
    print(assertion)
    # print(base64.b64decode(assertion))
    print("#################################################################:")

    print("#################### URL ENCODED Saml Assertion for ECS STS API Call ###############################:")
    urlEncodedAssertion = urllib.parse.quote_plus(assertion)
    print(urlEncodedAssertion)
    print("#################################################################:")

    # Create our ECSSAMLAssertion class instance
    ecsassert = ECSSAMLAssertion(assertion)

    # Parse the returned assertion and extract the authorized roles
    awsroles = []
    root = ET.fromstring(base64.b64decode(assertion))
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                awsroles.append(saml2attributevalue.text)

    # Note the format of the attribute value should be role_arn,principal_arn
    # but lots of blogs list it as principal_arn,role_arn so let's reverse
    # them if needed
    for awsrole in awsroles:
        chunks = awsrole.split(',')
        if 'saml-provider' in chunks[0]:
            newawsrole = chunks[1] + ',' + chunks[0]
            index = awsroles.index(awsrole)
            awsroles.insert(index, newawsrole)
            awsroles.remove(awsrole)

    # If I have more than one role, ask the user which one they want,
    # otherwise just proceed
    print("")
    i = 0
    print("The following provider/role combinations are contained in the provided SAML Assertion "
          "and can be used with the with teh ECS AssumeRoleWithSAML STS api call")
    for awsrole in awsroles:
        ecsassert.roles.append(awsrole.split(',')[0])
        ecsassert.providers.append(awsrole.split(',')[1])
        print('[', i, ']: ', awsrole.split(',')[0], awsrole.split(',')[1])
        i += 1
    return ecsassert


"""
Main 
"""
if __name__ == "__main__":
    try:
        # Create object to support controlled shutdown
        controlledShutdown = ECSDataCollectionShutdown()

        # Dump out application path
        currentApplicationDirectory = os.getcwd()
        configFilePath = os.path.abspath(os.path.join(currentApplicationDirectory, "configuration", CONFIG_FILE))
        tempFilePath = os.path.abspath(os.path.join(currentApplicationDirectory, "temp"))

        # Create temp directory if it doesn't already exists
        if not os.path.isdir(tempFilePath):
            os.mkdir(tempFilePath)
        else:
            # The directory exists so lets scrub any temp XML files out that may be in there
            files = os.listdir(tempFilePath)
            for file in files:
                if file.endswith(".xml"):
                    os.remove(os.path.join(currentApplicationDirectory, "temp", file))

        print(MODULE_NAME + "::__main__::Current directory is : " + currentApplicationDirectory)
        print(MODULE_NAME + "::__main__::Configuration file path is: " + configFilePath)

        # Initialize configuration and VDC Lookup
        log_it = ecs_config(configFilePath, tempFilePath)

        # Initialize connection(s) to ECS
        if ecs_authenticate():
            # We've authenticated and have a validated configuration at this point lets run the demo to
            # 1. Prompt for AD credentials
            # 2. Perform and SSO Login to our configured IdP
            # 3. Process returned HTML form to set the user and password and submit the form
            # to retrieve a SAML assertion
            # 4. URL Encode the SAML Assertion
            # 5. Call the ECS STS API to perform an AssumeRoleWithSAML Call to get a temporary set of credentials

            # Gather credentials and IDP URL
            print("Enter AD User:")
            username = input()
            password = getpass.getpass()
            print('')

            # Perform the SSO login to the IDP and process the assertion
            saml_assertion = ecs_ido_sso_login(username, password)

            # If we have a valid assertion make a call the ECS STS API using the
            # first role / provider combination in the assertion object
            if not (saml_assertion is None):
                ECSDataCollection("ecs_assume_role_saml", log_it, _ecsManagmentAPI, tempFilePath, saml_assertion)

            # Exit

    except Exception as e:
        print(MODULE_NAME + '__main__::The following unexpected error occured: '
              + str(e) + "\n" + traceback.format_exc())