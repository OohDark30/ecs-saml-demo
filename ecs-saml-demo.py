"""
""
"""
import base64
import urllib
import urllib.parse
import requests
from bs4 import BeautifulSoup
from configuration.ecs_saml_demo_configuration import ECSSAMLConfiguration
from logger import ecs_logger
from ecs.ecs import ECSAuthentication
from ecs.ecs import ECSApi
import errno
import getpass
import os
import traceback
import signal
import time
import logging
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
_ecsApi = list()
_stsAccessKeyId = None
_stsSecretKey = None
_stsSessionToken = None

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


class ECSDataCollection:
    def __init__(self, method, logger, ecs_api_input, tempdir, saml_assertion_input, index_role_to_assume_input):
        self.method = method
        self.logger = logger
        self.ecs_api = ecs_api_input
        self.tempdir = tempdir
        self.assertion = saml_assertion_input
        self.index_role_to_assume = index_role_to_assume_input

        logger.info(MODULE_NAME + '::ECSDataCollection()::init method of class called')

        try:
            self.logger.info(MODULE_NAME + '::ECSDataCollection()::Starting method: ' + self.method)

            if self.method == 'ecs_assume_role_saml':
                ecs_assume_role_saml(self.logger, self.ecs_api, self.tempdir, self.assertion, self.index_role_to_assume)
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
        self.shortRoles = []

    def addRole(self, role):
        self.roles.append(role)

    def addShortRole(self, role):
        self.shortRoles.append(role)

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


def ecs_assume_role_saml(logger, ecsmanagmentapi, tempdir, assertion, index_of_role_to_assume):
    global _stsAccessKeyId
    global _stsSecretKey
    global _stsSessionToken

    try:
        # Perform API call against each configured ECS
        for ecsconnection in ecsmanagmentapi:

            # for each role / provider combination call the AssumeRoleWithSAML STS API
            i = 0
            assertion_saml = assertion.saml_assertion
            while i < 1:
                assume_role_with_saml_data = ecsconnection.assume_role_with_saml(assertion_saml,
                                                                                 assertion.roles[index_of_role_to_assume],
                                                                                 assertion.providers[index_of_role_to_assume], tempdir)
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
                        _stsAccessKeyId = aws_access_key_id
                        _stsSecretKey = aws_secret_access_key
                        _stsSessionToken = aws_session_token

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


def s3_create_bucket(logger, ecs_connection_input, access_key, secret_key, session_token, bucket_name):
    global _configuration
    global _logger
    global _ecsAuthentication

    try:
        ecs_connection_input.s3_create_bucket(access_key, secret_key, session_token, 9020, bucket_name)
    except Exception as ex:
        raise ex


def s3_delete_bucket(logger, ecs_connection_input, access_key, secret_key, session_token, bucket_name):
    global _configuration
    global _logger
    global _ecsAuthentication

    try:
        ecs_connection_input.s3_delete_bucket(access_key, secret_key, session_token, 9020, bucket_name)
    except Exception as ex:
        raise ex


def s3_create_object(logger, ecs_connection_input, access_key, secret_key, session_token, bucket_name, object_name, object_content, user_meta_data):
    global _configuration
    global _logger
    global _ecsAuthentication

    try:
        ecs_connection_input.s3_create_object(access_key, secret_key, session_token, 9020, bucket_name, object_name, object_content, user_meta_data)
    except Exception as ex:
        raise ex


def s3_delete_object(logger, ecs_connection_input, access_key, secret_key, session_token, bucket_name, object_name):
    global _configuration
    global _logger
    global _ecsAuthentication

    try:
        ecs_connection_input.s3_delete_object(access_key, secret_key, session_token, 9020, bucket_name, object_name)
    except Exception as ex:
        raise ex


def ecs_authenticate():
    global _ecsAuthentication
    global _configuration
    global _logger
    global _ecsApi
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
                _ecsApi.append(ECSApi(auth, ecsconnection['connectTimeout'],
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
    global _ecsApi

    try:
        # Wait till configuration is set
        while not _configuration:
            time.sleep(1)

        # Now lets spin up a thread for each API call with it's own custom polling interval by iterating
        # through our module configuration
        for i, j in _configuration.modules_intervals.items():
            method = str(i)
            interval = str(j)
            t = ECSDataCollection(method, _influxClient, _logger, _ecsApi, interval,
                                  _configuration.tempfilepath)
            t.start()

    except Exception as e:
        _logger.error(MODULE_NAME + '::ecs_data_collection()::A failure occurred during data collection. Cause: '
                      + str(e) + "\n" + traceback.format_exc())


def ecs_test_sts_temp_credentials():
    global _logger
    global _configuration
    global _ecsAuthentication
    global _ecsApi
    global _stsAccessKeyId
    global _stsSecretKey
    global _stsSessionToken

    # Create the configured # of bucket(s)
    buckets_to_create = _configuration.test_data_generation['numberOfBuckets']
    objects_to_create = _configuration.test_data_generation['numberOfObjects']
    bucketPrefix = _configuration.test_data_generation['bucketPrefix']
    objectPrefix = _configuration.test_data_generation['objectPrefix']
    objectContentTemplate = _configuration.test_data_generation['objectContentTemplate']
    userMetadataHeaderPrefix = _configuration.test_data_generation['userMetadataHeaderPrefix']

    # Generate dictionary of user meta data
    user_metadata_dictionary = {}

    # Iterate thru dictionary of user meta data attributes to add
    # and generate
    for list_dict in _configuration.user_metadata:
        user_metadata_dictionary[list_dict['key']] = list_dict['value']

    # Create the configured # of objects in the bucket using the
    # user meta-data attributes for the configured ECS Clusters
    for ecs_connection in _ecsApi:
        i = 1
        try:
            while i <= int(buckets_to_create):
                # Create the bucket

                s3_create_bucket(_logger, ecs_connection, _stsAccessKeyId, _stsSecretKey, _stsSessionToken, (bucketPrefix + "-" + str(i)))

                # Create the objects in the bucket
                j = 1
                while j <= int(objects_to_create):
                    object_data = objectContentTemplate + str(j)
                    s3_create_object(_logger, ecs_connection, _stsAccessKeyId, _stsSecretKey, _stsSessionToken, (bucketPrefix + "-" + str(i)), (objectPrefix + "-" + str(j)), object_data, user_metadata_dictionary)
                    j += 1

                i += 1

            # Now delete the objects and buckets created
            k = 1
            while k <= int(buckets_to_create):
                # Delete the objects in the bucket
                m = 1
                while m <= int(objects_to_create):

                    s3_delete_object(_logger, ecs_connection, _stsAccessKeyId, _stsSecretKey, _stsSessionToken, (bucketPrefix + "-" + str(k)), (objectPrefix + "-" + str(m)))
                    m += 1

                s3_delete_bucket(_logger, ecs_connection, _stsAccessKeyId, _stsSecretKey, _stsSessionToken, (bucketPrefix + "-" + str(k)))
                k += 1
        except Exception as ex:
            _logger.error(MODULE_NAME + '::ecs_test_sts_temp_credentials::Unexpected error encountered. Cause: '
                          + str(ex))
            break


def prepare_saml_request():
    return {
        "https": "off",
        'http_host': '10.154.48.63:8000',
        'script_name': '/',
        'server_port': '',
        'get_data': '',
        'post_data': ''
    }


def ecs_ido_sso_login(username, password, configFilePath):
    global _logger
    global _configuration

    # Initiate session handler
    session = requests.Session()

    # Programmatically get the SAML assertion
    # Opens the initial IdP url and follows all of the HTTP302 redirects, and
    # gets the resulting login page
    sslverification = False
    formresponse = session.get(_configuration.saml_idp_url, verify=sslverification)

    # Debug the response code if needed
    #print(formresponse.status_code)

    # Return logic - Seen the need for this in some Ping Federate environments
    while formresponse.status_code == 401:
        formresponse = session.get(formresponse.url)

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
        # Check for PingFederate login form
        if action and loginid == "loginForm":
            parsedurl = urllib.parse.urlparse(_configuration.saml_idp_url)
            idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action
        # Check for Keycloak login form
        if loginid == "kc-form-login":
            idpauthformsubmiturl = action

    # Performs the submission of the IdP login form with the above post data
    response = session.post(
        idpauthformsubmiturl, data=payload, verify=sslverification)

    # Debug the response if needed
    #print(response.text)

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
    ecsAssertion = ECSSAMLAssertion(assertion)

    # Parse the returned assertion and extract the authorized roles
    awsRoles = []
    root = ET.fromstring(base64.b64decode(assertion))
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role':
            for saml2AttributeValue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                awsRoles.append(saml2AttributeValue.text)

    # Note the format of the attribute value should be role_arn,principal_arn
    # but lots of blogs list it as principal_arn,role_arn so let's reverse
    # them if needed
    for awsRole in awsRoles:
        chunks = awsRole.split(',')
        if 'saml-provider' in chunks[0]:
            newAwsRole = chunks[1] + ',' + chunks[0]
            index = awsRoles.index(awsRole)
            awsRoles.insert(index, newAwsRole)
            awsRoles.remove(awsRole)

    # If I have more than one role, ask the user which one they want,
    # otherwise just proceed
    print("")
    i = 0
    print("The following provider/role combinations are contained in the provided SAML Assertion "
          "and can be used with the with teh ECS AssumeRoleWithSAML STS api call")
    _samlAssertionRoles = {}
    for awsRole in awsRoles:
        stringFullRoleArn = awsRole.split(',')[0]
        ecsAssertion.roles.append(stringFullRoleArn)
        stringShortRole = stringFullRoleArn.split('/')[1]
        ecsAssertion.shortRoles.append(stringShortRole)
        ecsAssertion.providers.append(awsRole.split(',')[1])
        print('[', i, ']: ', awsRole.split(',')[0], awsRole.split(',')[1])
        i += 1
    return ecsAssertion

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
        configDirectory = os.path.abspath(os.path.join(currentApplicationDirectory, "configuration"))
        tempFilePath = os.path.abspath(os.path.join(currentApplicationDirectory, "temp"))

        # Create temp directory if needed
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
            username = input("Enter the IdP User Name.  Typically an Active Directory User:")
            password = getpass.getpass(prompt='Enter your password: ')

            # Perform the SSO login to the IDP and process the assertion
            saml_assertion = ecs_ido_sso_login(username, password, configDirectory)

            # If we have a valid assertion make a call the ECS STS API using the
            # first role / provider combination in the assertion object
            if not (saml_assertion is None):
                # First lets have the user select the role from the assertion they want to assume role with
                while True:
                    print("Please enter the name of one of the following roles contained in the assertion that you "
                          "want to assume:\r\n\t\t")
                    roleToAssume = input(saml_assertion.shortRoles)

                    bRoleExists = False
                    index_of_role_to_assume = 0
                    for r in saml_assertion.shortRoles:
                        if r == roleToAssume:
                            bRoleExists = True
                            break
                        else:
                            index_of_role_to_assume += 1

                    if not bRoleExists:
                        print("The role entered does not exist in the SAML Assertion.\r\n")
                        continue
                    else:
                        if ECSDataCollection("ecs_assume_role_saml", log_it, _ecsApi, tempFilePath, saml_assertion, index_of_role_to_assume):
                            # The SAML assertion call completed now lets generate some data if we're configured for it.
                            generate_test_data = _configuration.test_data_generation['generate_data']
                            if generate_test_data in ['Y', 'y']:
                                if ecs_test_sts_temp_credentials():
                                    print("#################### Test Data Generation Processing Completed Successfully "
                                          "with Temporary Credentials ###############################:")
                                    log_it.info(MODULE_NAME + '::__main__::Completed processing successfully.')
                                else:
                                    print("#################### Test Data Generation Failed with Temporary Credentials.  "
                                          "Please check logs ###############################:")
                                    log_it.info(MODULE_NAME + '::__main__::Completed processing with errors.  Please '
                                                              'check the logs.')
                            else:
                                print("#################### Skipping Test Data Generation - Processing Completed Successfully "
                                      "with Temporary Credentials ###############################:")
                                log_it.info(MODULE_NAME + '::__main__::Completed processing successfully.')
                        break

    except Exception as e:
        print(MODULE_NAME + '__main__::The following unexpected error occurred: '
              + str(e) + "\n" + traceback.format_exc())
