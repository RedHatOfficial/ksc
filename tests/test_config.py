#!/usr/bin/python3

import os
import unittest
from copy import deepcopy
import tempfile

from utils import getconfig
from utils import ConfigNotFoundException
from utils import ConfigMissingMandatoryFieldException
from utils import ConfigMalformedFieldException
from utils import ConfigDeprecatedValueException
from utils import SubmissionMethod

class ConfigTestCase(unittest.TestCase):
    
    validConfigInput = {
        "user": "some@user.com",
        "partner": "some_partner",
        "server": "https://bugzilla.example.com/xmlrpc.cgi",
        "partnergroup": "some_group",
        "api_key": "0123456789abcdef",
        "to": "some@list.com"
    }

    @staticmethod
    def writeConfigKeyValuePair(fp, key, value):
        fp.write(f"{key}={value}\n")

    @staticmethod
    def configFromDict(path, dic):
        with open(path, "w") as fp:
            for key in dic:
                ConfigTestCase.writeConfigKeyValuePair(fp, key, dic[key])

    def setUp(self):
        fd, self.configFile = tempfile.mkstemp()
        os.close(fd)

    def tearDown(self):
        os.unlink(self.configFile)

class BlankConfigTestCase(unittest.TestCase):
    def test_FailOnMissing(self):
        with self.assertRaises(ConfigNotFoundException) as context:
            getconfig("/invalid.path", False, False, False)

class ValidConfigTestCase(ConfigTestCase):
    def setUp(self):
        super().setUp()

    def test_AssertValidValues(self):
        configInput = deepcopy(self.validConfigInput)
        ConfigTestCase.configFromDict(self.configFile, configInput)
        result = getconfig(self.configFile, False, False, False)
        for key in configInput:
            res_key = key
            if res_key == "partnergroup":
                res_key = "group"
            self.assertEqual(result[res_key], configInput[key])

class InvalidConfigTestCase(ConfigTestCase):
    def setUp(self):
        super().setUp()

    def test_LegacyDefaultValues_RaiseException(self):
        defaultValues = {
            "user": "user@redhat.com",
            "partner": "partner-name",
            "partnergroup": "partner-group",
            "api_key": "api_key"
        }
        for defaultKey in defaultValues:
            configInput = deepcopy(self.validConfigInput)
            configInput[defaultKey] = defaultValues[defaultKey]
            ConfigTestCase.configFromDict(self.configFile, configInput)

            with self.assertRaises(ConfigDeprecatedValueException) as context:
                result = getconfig(self.configFile, False, False, False)

    def test_BlankMandatory_RaiseException(self):
        configInput = deepcopy(self.validConfigInput)
        del configInput["user"]
        ConfigTestCase.configFromDict(self.configFile, configInput)
        with self.assertRaises(ConfigMissingMandatoryFieldException) as context:
            result = getconfig(self.configFile, False, False, False)

        configInput = deepcopy(self.validConfigInput)
        del configInput["partnergroup"]
        ConfigTestCase.configFromDict(self.configFile, configInput)
        with self.assertRaises(ConfigMissingMandatoryFieldException) as context:
            result = getconfig(self.configFile, False, False, False)

        configInput = deepcopy(self.validConfigInput)
        del configInput["to"]
        del configInput["api_key"]
        ConfigTestCase.configFromDict(self.configFile, configInput)

        with self.assertRaises(ConfigMissingMandatoryFieldException) as context:
            result = getconfig(self.configFile, False, False, False)

    def test_MalformedServer_RaiseException(self):
        configInput = deepcopy(self.validConfigInput)
        configInput["server"] = "https://bugzilla.example.com/xmlrpc.foo"
        ConfigTestCase.configFromDict(self.configFile, configInput)

        with self.assertRaises(ConfigMalformedFieldException) as context:
            result = getconfig(self.configFile, False, False, False)

    def test_ExpectedMethods_Match(self):
        configInput = deepcopy(self.validConfigInput)
        ConfigTestCase.configFromDict(self.configFile, configInput)
        result = getconfig(self.configFile, False, False, False)

        exp_method = SubmissionMethod.NONE.value
        exp_method |= SubmissionMethod.BUGZILLA.value
        exp_method |= SubmissionMethod.MAILING_LIST.value
        self.assertEqual(result['method'], exp_method)

        configInput = deepcopy(self.validConfigInput)
        del configInput["server"]
        del configInput["api_key"]
        ConfigTestCase.configFromDict(self.configFile, configInput)
        result = getconfig(self.configFile, False, False, False)

        exp_method = SubmissionMethod.NONE.value
        exp_method |= SubmissionMethod.MAILING_LIST.value
        self.assertEqual(result['method'], exp_method)

        configInput = deepcopy(self.validConfigInput)
        del configInput["to"]
        ConfigTestCase.configFromDict(self.configFile, configInput)
        result = getconfig(self.configFile, False, False, False)

        exp_method = SubmissionMethod.NONE.value
        exp_method |= SubmissionMethod.BUGZILLA.value
        self.assertEqual(result['method'], exp_method)

    def test_PartnerOrGroupNoneValuesStripped(self):
        for key_list in [["partner"], ["group"], ["partner", "group"]]:
            configInput = deepcopy(self.validConfigInput)
            for key in key_list:
                key = key if key != "group" else "partnergroup"
                configInput[key] = "none"
            ConfigTestCase.configFromDict(self.configFile, configInput)
            result = getconfig(self.configFile, False, False, False)
            for key in key_list:
                self.assertEqual(result[key], "")

if __name__ == '__main__':
    unittest.main()
