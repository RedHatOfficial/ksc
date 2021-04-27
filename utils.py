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

from bugzilla import Bugzilla, BugzillaError

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


def getconfig(path='/etc/ksc.conf', mock=False):
    """
    Returns the bugzilla config
    """
    result = {}
    result['partner'] = ''

    if not os.path.isfile(path):
        path = '/etc/ksc.conf'
    try:
        fptr = open(path)
        lines = fptr.readlines()
        fptr.close()
        for line in lines:
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
        if 'user' not in result and 'api_key' not in result:
            print("Either user name or api_key must be specified in configuration.")
            return False
        if ('server' not in result or
                not result['server'].endswith('xmlrpc.cgi')):
            print("Servername is not valid in configuration.")
            return False
        if not mock:  # pragma: no cover
            if not result['partner'] or result['partner'] == 'partner-name':
                result["partner"] = input("Partner name: ")
            if not result['group'] or result['group'] == 'partner-group':
                result['group'] = input("Partner group: ")
            if "api_key" not in result or not result['api_key'] or result['api_key'] == 'api_key':
                print('Current Bugzilla user: %s' % result['user'])
                result['password'] = getpass.getpass('Please enter password: ')
            else:
                print('Using API Key for authentication')
        else:
            result['password'] = 'mockpassword'
        if not result['user']:
            print("Error: missing values in configuration file.")
            print("Bug not submitted")
            sys.exit(1)
    except Exception as err:
        print("Error reading %s" % path)
        sys.exit(1)
    return result


def createbug(filename, arch, mock=False, path='/etc/ksc.conf',
              releasename='7.0', module=None):
    """
    Opens a bug in the Bugzilla
    """

    if releasename.startswith('6.'):
        bughash = {'product': 'Red Hat Enterprise Linux 6'}
    elif releasename.startswith('7.'):
        bughash = {'product': 'Red Hat Enterprise Linux 7'}
    elif releasename.startswith('8.'):
        bughash = {'product': 'Red Hat Enterprise Linux 8'}
    else:
        print("Invalid releasename: Bug not created")
        return
    bughash["component"] = 'kernel'
    bughash["summary"] = "kABI Symbol Usage"
    bughash["version"] = releasename
    bughash["platform"] = arch
    bughash["severity"] = "medium"
    bughash["priority"] = "medium"
    bughash["description"] = "Creating the bug to attach the symbol " + \
                             "usage details."
    bughash["qa_contact"] = "kernel-qe@redhat.com"
    groups = []

    if module:
        bughash["summary"] += " ({})".format(str(module))

    # We change the path if only it is mock
    if mock:
        print("Using local config file data/ksc.conf")
        path = './data/ksc.conf'

    try:
        conf = getconfig(path, mock=mock)
    except Exception as err:
        print("Problem in parsing the configuration.")
        print(err)
        return

    if not conf:
        return
    if 'group' in conf:
        if conf['group'] != 'partner-group':
            groups.append(conf['group'])

    groups = list(filter(lambda x: len(x) > 0, groups))
    if not groups:
        print("Error: Please specify a non-empty partner-group config " +\
              "option in your ksc.conf config file or in the prompt above. " +\
              "Bug was not filed!")
        return

    bughash["groups"] = groups

    if 'api_key' in conf and conf['api_key'] != 'api_key':
        bughash["Bugzilla_api_key"] = conf["api_key"]
    else:
        bughash["Bugzilla_login"] = conf["user"]
        bughash["Bugzilla_password"] = conf["password"]
    bughash["cf_partner"] = [conf["partner"], ]
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

    bughash["sub_component"] = 'kabi-stablelists'

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
