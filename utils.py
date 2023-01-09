# Copyright 2012,2018 Red Hat Inc.
# Author: Kushal Das <kdas@redhat.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.  See
# http://www.gnu.org/copyleft/gpl.html for the full text of the
# license.
#

"""
Helper functions for ksc.
"""

import os
import re
import sys
import time
import getpass
import subprocess
import locale

from enum import Enum

from bugzilla import Bugzilla, BugzillaError

import smtplib
from email.utils import formatdate
from email.mime.text import MIMEText

class SubmissionMethod(Enum):
    NONE = 0
    BUGZILLA = 1 << 0
    MAILING_LIST = 1 << 1

class ConfigNotFoundException(Exception):
    def __init__(self, filepath):
        message = f"{filepath}: Could not open config file."
        super().__init__(message)

class ConfigMissingMandatoryFieldException(Exception):
    def __init__(self, filepath, field, opt=""):
        opt = f" {opt}" if opt else opt
        if type(field) is str:
            message = f"{filepath}: Mandatory field `{field}' not found.{opt}"
        elif type(field) is list:
            message = f"{filepath}: At least one of the following fields " + \
                "must be set :" + ", ".join(map(lambda x: f"`{x}'", field))
        super().__init__(message)

class ConfigMalformedFieldException(Exception):
    def __init__(self, filepath, field, value, opt=""):
        opt = f" {opt}" if opt else opt
        message = f"{filepath}: Field `{field}' has an invalid value: " + \
            "`{value}'.{opt}"
        super().__init__(message)

class ConfigDeprecatedValueException(Exception):
    def __init__(self, filepath, field, value):
        message = f"{filepath}: Field `{field}' is set to a deprecated " + \
            "value: `{value}'. Please consult ksc manpage (man ksc)."
        super().__init__(message)

# stablelist directory
WHPATH = '/lib/modules'
# Module.symvers directory
SRCPATH = '/usr/src/kernels'

def query_user(query, max_tries=10, is_valid=lambda x: len(x) > 0):
    """
    Queries user for a value.

    :arg query:     query string
    :arg max_tries: maximal number of times user will be prompted to give a
                    valid reply (avoid cycling)
    :arg is_valid:  lambda function that determines if and when user supplied
                    input is valid

    :return         response     if valid
    :return         ""           if received max_tries invalid reponses
    :return         ""           if we couldn't read data from stdin
    """
    tries_left = max_tries
    response = ""
    while not is_valid(response):
        if tries_left < max_tries:
            if response == "":
                print("Empty response received. Please try again.")
            else:
                print("Option `%s' is invalid. Please try again." % response)

        if tries_left == 0:
            print("Reached maximum number of invalid responses.")
            return ""

        try:
            tries_left = tries_left - 1
            response = input(query)
        except EOFError:
            print("Reached early EOF.")
            return ""

    return response

def query_user_bool(query):
    """
    Queries user for a Y/N value

    :arg query:     query string
    :return         response     if valid
    :return         ""           if received max_tries invalid reponses
    :return         ""           if we couldn't read data from stdin
    """
    check_fx = lambda x: x.lower() in ['y', 'n']
    return query_user(query, is_valid=check_fx)

def get_release_name():
    if not os.path.isfile('/etc/redhat-release'):
        print('This tool needs to run on Red Hat Enterprise Linux')
        return None

    with open('/etc/redhat-release', 'r') as fptr:
        release = fptr.read().split(' ')
        if len(release) <= 6:
            print('This tool needs to run on Red Hat Enterprise Linux')
            return None
    for rel in release:
        if re.match("\d.\d+",rel):
            return rel
    print('This tool needs to run on Red Hat Enterprise Linux')
    return None

def read_list(arch, kabipath, verbose=False):
    """
    Reads a stablelist file and returns the symbols
    """
    result = []
    fpath = os.path.join(WHPATH, kabipath, "kabi_stablelist_%s" % arch)
    if not os.path.isfile(fpath):
        fpath = os.path.join(WHPATH, kabipath, "kabi_whitelist_%s" % arch)
    if not os.path.isfile(fpath):  # pragma: no cover
        print("File not found:", fpath)
        return [], False
    try:
        if verbose:  # pragma: no cover
            print("Reading %s" % fpath)
        fptr = open(fpath)
        for line in fptr.readlines():
            if line.startswith("["):
                continue
            result.append(line.strip("\n\t"))
        fptr.close()
    except IOError as err:  # pragma: no cover
        print(err)
        print("stablelist missing")

    return result, True


def read_total_list(symvers=None):
    """
    Reads total symbol list and returns the list
    """
    if not symvers:
        release = os.uname()[2]
        symvers = os.path.join(SRCPATH, release, "Module.symvers")
    if not os.path.isfile(symvers):  # pragma: no cover
        print("File not found:", symvers)
        print("Do you have current kernel-devel package installed?")
        sys.exit(1)
    result = []
    try:
        with open(symvers, "r") as fptr:
            for line in fptr.readlines():
                if line.startswith("["):
                    continue  # pragma: no cover
                result.append(line.split()[1])
    except IOError as err:  # pragma: no cover
        print(err)
        print("Missing all symbol list")
    return result


def run(command):
    """
    runs the given command
    """
    env = os.environ.copy()
    if "LANG" in env:
        env["LANG"] = 'C'
    ret = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           close_fds=True, env=env)
    out, err = ret.communicate()
    if err:
        errs = err.decode(locale.getpreferredencoding()).split(':', 1)
        raise IOError(errs[1].strip() if len(errs) > 1 else err)
    return out.decode(locale.getpreferredencoding())

def is_valid_mail(email):
    return re.fullmatch(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', email)

def getconfig(path='/etc/ksc.conf', mock=False, require_partner=False, verbose=True):
    """
    Returns the bugzilla config
    """
    result = {}
    result['partner'] = ''
    result['method'] = SubmissionMethod.NONE.value

    if not os.path.isfile(path):
        path = '/etc/ksc.conf'
    try:
        fptr = open(path)
        lines = fptr.readlines()
        fptr.close()
    except Exception as err:
        raise ConfigNotFoundException(path)

    # To be deprecated in the future:
    result['bugzilla_enable'] = True

    cat = None
    for line in lines:
        if not line:
            continue
        m = re.match(r'^\[([^]]*)\]$', line)
        if m:
            cat = m.groups()[0]
        if line.startswith("user="):
            result["user"] = line[5:-1]
        elif line.startswith("partner="):
            result["partner"] = line[8:-1]
        elif line.startswith("server="):
            result["server"] = line[7:-1]
        elif line.startswith("partnergroup="):
            result["group"] = line[13:-1]
        elif line.startswith("api_key="):
            result["api_key"] = line[8:-1]
        elif line.startswith("to="):
            result["to"] = line[3:-1]
        elif line.startswith("smtp="):
            result["smtp"] = line[5:-1]
        elif line.startswith("enable="):
            result[f"{cat}_enable"] = bool(int(line[7:-1]))

    if 'user' not in result or not result['user']:
        raise ConfigMissingMandatoryFieldException(path, "user")

    if not is_valid_mail(result['user']):
        raise ConfigMalformedFieldException(path, "user", result['user'],
            "Please provide a valid e-mail address.")

    if 'partner' not in result or not result['partner']:
        raise ConfigMissingMandatoryFieldException(path, "partner")

    if 'group' not in result or not result['group']:
        raise ConfigMissingMandatoryFieldException(path, "group")

    if result['partner'] == "none":
        result['partner'] = ""

    if result['group'] == "none":
        result['group'] = ""

    mandatory_set = False
    if 'to' in result and result['to']:
        if not is_valid_mail(result['to']):
            raise ConfigMalformedFieldException(path, "to", result['to'],
                "Please provide a valid e-mail address.")
        result['method'] |= SubmissionMethod.MAILING_LIST.value
        mandatory_set = True

    if 'api_key' in result and result['api_key']:
        if 'server' not in result or not result['server']:
            raise ConfigMissingMandatoryFieldException(path, "user",
                "Field `api_key' requires `server' field, which was not set.")
        if not result['server'].endswith('xmlrpc.cgi'):
            raise ConfigMalformedFieldException(path, "server", result['server'],
                "Please provide a valid RPC URL, e.g., " +
                "`https://bugzilla.redhat.com/xmlrpc.cgi'.")
        result['method'] |= SubmissionMethod.BUGZILLA.value
        mandatory_set = True

    if not mandatory_set:
        raise ConfigMissingMandatoryFieldException(path, ["to", "api_key"])

    # ksc deprecated default values, ensure that users do not try to file a bug
    # using legacy configuration's default values
    deprecatedValues = {
        "user": "user@redhat.com",
        "partner": "partner-name",
        "group": "partner-group",
        "api_key": "api_key"
    }

    for key in deprecatedValues:
        if key not in result:
            continue
        if not result[key]:
            continue
        if result[key] != deprecatedValues[key]:
            continue
        raise ConfigDeprecatedValueException(path, key, result[key])

    if not (result['method'] & SubmissionMethod.BUGZILLA.value):
        conf["bugzilla_enable"] = False

    if not (result['method'] & SubmissionMethod.MAILING_LIST.value):
        conf["mailing_list_enable"] = False

    return result

def submit_stable(filename, arch, mock=False, path='/etc/ksc.conf',
              releasename='9.0', module=None):
    return submit(filename, arch, mock, path, releasename, module,
            "kabi-stablelists")

def submit_notif(filename, arch, mock=False, path='/etc/ksc.conf',
              releasename='9.0', module=None):
    return submit(filename, arch, mock, path, releasename, module,
            "kabi-notificationlists")

def submit(filename, arch, mock, path, releasename, module, subcomponent,
        require_partner = False):
    if mock:
        print("Using local config file data/ksc.conf")
        path = './data/ksc.conf'

    try:
        conf = getconfig(path, mock, require_partner)
    except Exception as err:
        print("Problem in parsing the configuration.")
        print(err)
        return

    if conf["bugzilla_enable"]:
        print("Bugzilla: enabled")
        createbug(filename, arch, mock, conf, releasename, module,
                  subcomponent, require_partner)
    else:
        print("Bugzilla: disabled")

    if conf["mailing_list_enable"]:
        print("Mailing list: enabled")
        sendmail(filename, arch, mock, conf, releasename, module,
                 subcomponent, require_partner)
    else:
        print("Mailing list: disabled")

def get_major_release(releasename):
    centos = releasename[1]
    releasename = releasename[0]

    major = releasename.split(".")
    if len(major) < 2 or not releasename.split(".")[0].isnumeric():
        return None, None

    return int(releasename.split(".")[0]), centos

def sendmail(filename, arch, mock, conf, releasename, module, subcomponent,
        require_partner = False):
    """
    Email ksc report.
    """

    major, centos = get_major_release(releasename)
    if not major:
        print("Invalid releasename: Mail not sent.")
        return

    body  = f"Product:  Red Hat Enterprise Linux {major}\n"
    body += f"Release:  Centos Stream\n"
    body += f"Platform: {arch}\n"

    if 'group' in conf and conf['group'] != 'partner-group':
        body += f"Partner Group: {conf['group']}\n"

    if 'partner' in conf:
        body += f"Partner: {conf['partner']}\n"

    body += "\n"
    body += str(module) + "\n"
    body += "\n"
    body += "---\n"
    body += "\n"

    with open(filename, "r") as fp:
        for line in fp:
            body += f"{line}\n"

    msg = MIMEText(body)
    msg['To'] = conf['to']
    msg['From'] = conf['user']
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = f"{subcomponent} subscription"

    smtp = smtplib.SMTP(conf['smtp'])
    smtp.sendmail(conf['user'], conf['to'], msg.as_string())
    smtp.close()

    print("Mail sent.")

def createbug(filename, arch, mock, conf, releasename, module, subcomponent,
        require_partner = False):
    """
    Opens a bug in the Bugzilla
    """

    major, centos = get_major_release(releasename)
    if not major:
        print("Invalid releasename: Bug not created")
        return

    bughash = {'product': f"Red Hat Enterprise Linux {major}"}

    bughash["component"] = 'kernel'
    bughash["summary"] = "kABI Symbol Usage"
    bughash["version"] = releasename[0] if not centos else "CentOS Stream"
    bughash["platform"] = arch
    bughash["severity"] = "medium"
    bughash["priority"] = "medium"
    bughash["description"] = "Creating the bug to attach the symbol " + \
                             "usage details."
    bughash["qa_contact"] = "kernel-qe@redhat.com"

    if module:
        bughash["summary"] += " ({})".format(str(module))

    if 'group' in conf and conf['group']:
        bughash["groups"] = [conf['group']]

    if 'api_key' in conf and conf['api_key'] != 'api_key':
        bughash["Bugzilla_api_key"] = conf["api_key"]
    else:
        bughash["Bugzilla_login"] = conf["user"]
        bughash["Bugzilla_password"] = conf["password"]

    if conf["partner"]:
        bughash["cf_partner"] = [conf["partner"], ]
    else:
        if require_partner:
            print("You must provide a valid non-empty Partner field when using -s.")
            sys.exit(1)
        if query_user_bool("You have provided blank partner field. " \
                "This will file your request publicly. Proceed? [y/N]: ") != 'y':
            print("ksc-report.txt not uploaded. Terminating...")
            sys.exit(1)

    bughash["keywords"] = ["Tracking"]

    try:
        if 'api_key' in conf and conf['api_key'] != 'api_key':
            bz = Bugzilla(
                url=conf['server'],
                api_key=conf["api_key"]
            )
        else:
            bz = Bugzilla(
                url=conf['server'],
                user=conf["user"],
                password=conf["password"]
            )
    except BugzillaError as err:
        print("Bug not submitted. %s" % err)
        if not mock:
            sys.exit(1)

    if not mock:  # pragma: no cover
        print("Creating a new bug")

    bughash["sub_component"] = subcomponent

    # As it is as yet unclear whether the new sub_component will be
    # set up at the time of deployment, attemp to file with the old
    # sub_component as well.
    # If kabi-stablelists does not exist, an attempt to createbug
    # will cause an xmlrpc.client.Fault exception.
    try:
        trycreatebug(filename, mock, bughash, conf, bz)
    except Exception as err:  # pragma: no cover
        try:
            bughash["sub_component"] = 'kabi-whitelists'
            trycreatebug(filename, mock, bughash, conf, bz)
        except Exception as err:  # pragma: no cover
            print ("Could not create bug. %s" % err)
            if not mock:
                sys.exit(1)

def trycreatebug(filename, mock, bughash, conf, bz):

    bugid = 0

    if "groups" in bughash:
        ret = bz.build_createbug(
            product=bughash['product'],
            component=bughash['component'],
            sub_component=bughash['sub_component'],
            summary=bughash['summary'],
            version=bughash['version'],
            platform=bughash['platform'],
            qa_contact=bughash['qa_contact'],
            severity=bughash['severity'],
            priority=bughash['priority'],
            description=bughash['description'],
            groups=bughash['groups'],
            keywords=bughash['keywords']
        )
    else:
        ret = bz.build_createbug(
            product=bughash['product'],
            component=bughash['component'],
            sub_component=bughash['sub_component'],
            summary=bughash['summary'],
            version=bughash['version'],
            platform=bughash['platform'],
            qa_contact=bughash['qa_contact'],
            severity=bughash['severity'],
            priority=bughash['priority'],
            description=bughash['description'],
            keywords=bughash['keywords']
        )

    if "cf_partner" in bughash and bughash['cf_partner']:
        ret['cf_partner'] = bughash['cf_partner']

    bug = bz.createbug(ret)

    bugid = bug.id

    if not mock:  # pragma: no cover
        print("Bug URL %s/show_bug.cgi?id=%s" % \
              (conf['server'][:-11], bugid))
        print("Attaching the report")

    dhash = {}
    dhash["filename"] = "ksc-result.txt"
    dhash["contenttype"] = "text/plain"
    desc = "kABI symbol usage."

    for _ in range(3):
        with open(filename, "r") as fptr:
            attachment_id = bz.attachfile(bugid, fptr, desc, **dhash)

        if not mock:  # pragma: no cover
            if not attachment_id:
                time.sleep(1)
            else:
                print("Attached successfully as %s on bug %s" % (attachment_id, bugid))
                break
    else:
        print("Failed to attach symbol usage result")
        sys.exit()

    return bugid
