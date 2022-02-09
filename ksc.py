#!/usr/bin/env python3
# Copyright 2012,2018 Red Hat Inc.
# Author: Kushal Das <kdas@redhat.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.  See
# http://www.gnu.org/copyleft/gpl.html for the full text of the
# license.
#
import os
import re
import sys
from optparse import OptionParser, SUPPRESS_HELP
from utils import run, read_list
from utils import read_total_list, get_release_name
from utils import createbug
from utils import query_user, query_user_bool

KSCVERSION = "ksc - Version 1.8"


class Ksc(object):

    # RE to detect ksc cli execution
    HEADER_RE                 = re.compile(r"\[command: (?P<cmd>.*)\]")

    # RE to extract KO basename
    SECTION_KO_RE             = re.compile(r'{(?P<ko_file>.*)}')

    # RE to match with KO-body section
    LISTS_RE                  = re.compile(r'.*\[STABLELISTUSAGE\](?P<wl>.*)\[NONSTABLELISTUSAGE\]\s*(?P<gl>.*)', re.S)
    LISTS_RE_DEPRECATED       = re.compile(r'.*\[WHITELISTUSAGE\](?P<wl>.*)\[NONWHITELISTUSAGE\]\s*(?P<gl>.*)', re.S)

    # RE to extract symbol and its justification
    JUSTIFICATION_RE          = re.compile(r'#*\s*\((?P<symbol>.*)\)\s*(?P<justification>[^#]*)')

    # Non-stablelisted symbols justification free-form entries
    JUSTIFICATION_PLACEHOLDER = "ENTER JUSTIFICATION TEXT HERE"
    JUSTIFICATION_REFERENCE   = "JUSTIFICATION STATED UNDER `%s' SECTION"
    JUSTIFICATION_REF_DETECT  = re.compile(r"JUSTIFICATION STATED UNDER `(.*)' SECTION")
    JUSTIFICATION_SEPARATOR   = '#' * 10
    JUSTIFICATION_BODY        = '\n(%s)\n\n%s\n\n'

    # Sections
    # Note: there needn't be old-style declarations here, since this is used
    # for generation only.
    SECTION_STABLELISTS        = "[STABLELISTUSAGE]\n"
    SECTION_CO_STABLELISTS     = "[NONSTABLELISTUSAGE]\n"

    def __init__(self, mock=False):
        """
        Init call
        """
        self.all_symbols_used = {}
        self.nonstable_symbols_used = {}
        self.stable_symbols = {}
        self.defined_symbols = {}
        self.justified_symbols = {}
        self.justifications = {}
        self.matchdata = None
        self.total = None
        self.verbose = False
        self.mock = mock
        self.releasedir = None
        self.symvers = None
        self.arch = None
        self.vermagic = {}
        self.import_ns = {}
        if mock:
            self.releasename = '7.0'
        else:
            self.releasename = None

    def clean(self):
        self.all_symbols_used = {}
        self.nonstable_symbols_used = {}
        self.stable_symbols = {}
        self.defined_symbols = {}
        self.justified_symbols = {}
        self.justifications = {}
        self.matchdata = None
        self.total = None
        self.vermagic = {}
        self.import_ns = {}

    def main(self, mock_options=None):
        """
        Main function for the logic
        """
        filename = os.path.join(os.path.expanduser("~"), "ksc-result.txt")
        # default architecture
        self.arch = "x86_64"

        parser = OptionParser()
        parser.add_option("-c", "--config", dest="config",
                          help="path to configuration file", metavar="CONFIG")
        parser.add_option("-k", "--ko", action="append", dest="ko",
                          help="path to the ko file", metavar="KO")
        parser.add_option("-K", "--ko-dependency", action="append",
                          dest="ko_dependency", help="path to a dependency",
                          metavar="DEPENDENCY")
        parser.add_option("-n", "--name", dest="releasename",
                          help="Red Hat release to file the bug against, "
                               "e.g '6.7'", metavar="RELEASENAME")
        parser.add_option("-p", "--previous", dest="previous",
                          help="path to previous resultset to submit as bug")
        parser.add_option("-r", "--release", dest="release",
                          help="RHEL stablelist release to compare against, "
                               "e.g '6.7'", metavar="RELEASE")
        parser.add_option("-y", "--symvers", dest="symvers",
                          help="Path to the Module.symvers file. "
                               "The current kernel path is used if "
                               "not specified.",
                          metavar="SYMVERS")
        parser.add_option("-s", "--submit",
                          action="store_true", dest="submit", default=False,
                          help="Submit to Red Hat Bugzilla")
        parser.add_option("-v", "--version",
                          action="store_true", dest="VERSION", default=False,
                          help="Prints KSC version number")
        parser.add_option("-j", "--justification-from", action="append",
                          dest="justification_from", metavar="JUSTIFICATION",
                          help="read justification from previous ksc-result")

        if not self.mock:  # pragma: no cover
            (options, args) = parser.parse_args(sys.argv[1:])
        else:  # pragma: no cover
            (options, args) = parser.parse_args(mock_options)

        if options.VERSION:
            print(KSCVERSION)
            sys.exit(0)

        # Create the ksc.conf config path
        if options.config:
            path = os.path.abspath(os.path.expanduser(options.config))
        else:
            path = os.path.expanduser("~/ksc.conf")

        if options.releasename:
            self.releasename = options.releasename
            if not self.valid_release_version(self.releasename):
                sys.exit(1)

        if options.release:
            if not self.valid_release_version(options.release):
                sys.exit(1)

        if options.releasename and options.release and \
                options.release != options.releasename:
            print("Release and release name do not match.")
            sys.exit(1)

        if options.previous:  # Submit the result of previous run
            filename = os.path.abspath(os.path.expanduser(options.previous))
            if os.path.basename(filename) != 'ksc-result.txt':
                print("Please point to the ksc-result.txt file in -p option.")
                sys.exit(1)

            self.submit(filename, path)
            return

        self.releasedir = 'kabi-current'
        if options.release:
            if not self.valid_release_version(options.release):
                sys.exit(1)

            self.releasedir = 'kabi-rhel' + options.release.replace('.', '')

        if options.symvers:
            self.symvers = options.symvers

        if options.justification_from:
            for file in options.justification_from:
                self.read_justifications(file)

        if options.ko_dependency:
            for kmod_path in options.ko_dependency:
                self.parse_ko(kmod_path, process_stablelists=False)

        if options.ko:
            self.find_arch(options.ko)

            exists = self.read_data(self.arch, self.releasedir, self.symvers)
            # Return if there is any issue in reading stablelists
            if not exists:
                print(("Release %s for arch %s was not found.\n"
                      "Do you have right kernel-abi-stablelist installed ?" %
                       (self.releasedir, self.arch)))
                sys.exit(1)

            for kmod_path in options.ko:
                self.parse_ko(kmod_path, process_stablelists=True)

            self.remove_internal_symbols()

            for kmod_path in options.ko:
                self.print_result(kmod_path)

            self.save_result()

        else:  # pragma: no cover
            print("You need to provide a path to at least one .ko file.")
            sys.exit(1)

        # Now save the result

        if not options.submit:
            return

        if not self.mock:  # pragma: no cover
            self.get_justification(filename)
        self.submit(filename, path)

    def read_justifications(self, filepath):
        filepath = os.path.abspath(os.path.expanduser(filepath))

        if not os.path.isfile(filepath):
            print("Filename `%s' does not exist!" % filepath)
            return

        with open(filepath, "r") as fd:

            filename_section = ""

            for file_contents in re.split("({[^}]*})", fd.read()):

                filename_match = self.SECTION_KO_RE.match(file_contents)
                if filename_match:
                    filename_section = filename_match.group('ko_file')

                # Attempt to read new-style justifications, provided they are
                # present. Otherwise assume that old-style justifications were
                # given.
                match = self.LISTS_RE.match(file_contents)
                if not match:
                    match = self.LISTS_RE_DEPRECATED.match(file_contents)
                    if not match:
                        continue

                for symbol, justification in \
                        self.JUSTIFICATION_RE.findall(file_contents):
                    symbol = symbol.strip()
                    justification = justification.strip()

                    if justification == self.JUSTIFICATION_PLACEHOLDER:
                        continue

                    if self.JUSTIFICATION_REF_DETECT.match(justification):
                        continue

                    if filename_section not in self.justifications:
                        self.justifications[filename_section] = {}

                    self.justifications[filename_section][symbol] = \
                            justification

                    if symbol not in self.justified_symbols:
                        self.justified_symbols[symbol] = \
                                os.path.basename(filename_section)

    def valid_release_version(self, release):
        rels = release.split(".")
        if len(rels) != 2:
            print("Invalid release: %s" % release)
            return False
        if not rels[0].isdigit() or int(rels[0]) <= 5:
            print("Invalid release: %s" % release)
            return False
        return True

    def submit_get_consent(self):

        """
        Part of the submission process. User gets queried for Red Hat's
        receipt and internal use. Consent is mandatory.
        """

        consent_string = "By using ksc to upload your data to Red Hat, " \
            "you consent to Red Hat's receipt use and analysis of this " \
            "data. Do you agree? [y/N] "

        consent = query_user_bool(consent_string)
        if consent.lower() != 'y':
            print("Cannot proceed without consent. Qutting.")
            sys.exit(1)

    def submit_get_release(self):

        """
        Part of the submission process. User gets queried for release if
        not explicitly provided via argv.
        """

        # Release has been specified as argv, no need to query user at this time
        if self.releasename is not None:
            return

        print("RHEL release not specified with -n flag. Defaulting to your "
            "system's RHEL release.")

        self.releasename = get_release_name()
        use_sys_release  = ""
        if not self.releasename:
            print("Unable to determine system's release name. Please specify.")

        else:
            query = "File bug against RHEL release %s?" % self.releasename
            query += "\n"
            query += "y/N: "

            use_sys_release = query_user_bool(query)

            if not use_sys_release:
                print("Unable to determine user option. Qutting.")
                sys.exit(1)

        # Either system-determine RHEL release is not what user wishes to file
        # against, or ksc couldn't determine the release; query user to specify
        if use_sys_release.lower() == 'n' or not self.releasename:
            release_name = query_user(
                "Please enter valid RHEL release to file bug against: ",
                is_valid=self.valid_release_version
            )

            if not release_name:
                print("Unable to determine a valid RHEL release. Qutting.")
                sys.exit(1)

            else:
                print("Using RHEL %s release." % release_name)

            self.releasename = release_name

    def submit(self, filename, path):
        """
        Submits the resultset into Red Hat bugzilla.
        Asks user for Red Hat internal processing consent.
        If not set, determines and asks which RHEL release to use.

        :arg filename: Full path the ksc-result.txt file.
        :arg path: Path to the config file.
        """
        try:
            with open(filename, "r") as fptr:
                line = fptr.readline().strip()
                module_name = self.get_module_name(line)

        except IOError as err:
            print("Unable to read previous result: {}".format(err))
            sys.exit(1)

        if not self.mock:  # Ask for user permission
            self.submit_get_consent()
            self.submit_get_release()

        createbug(filename, self.arch, mock=self.mock, path=path,
                  releasename=self.releasename, module=module_name)

    def get_justification(self, filename):
        """
        Get the justification from User
        on non-stablelist symbols

        """
        bold = "\033[1m"
        reset = "\033[0;0m"

        print(bold)
        print('On the next screen, the result log will be opened to allow')
        print('you to provide technical justification on why these symbols')
        print('need to be included in the KABI stablelist.')
        print('Please provide sufficient information in the log, marked with ')
        print('the line below:')

        print(("\n%s\n" % self.JUSTIFICATION_PLACEHOLDER) + reset)
        print(bold + 'Press ENTER for next screen.' + reset)
        try:
            input()
        except EOFError:
            print("Warning. Running in a non-interactive mode.")

        editor = os.getenv('EDITOR')
        if editor:
            os.system(editor + ' ' + filename)
        else:
            os.system('vi ' + filename)
        return True

    def save_result(self):
        """
        Save the result in a text file
        """
        output_filename = os.path.expanduser("~/ksc-result.txt")
        if os.path.isfile(output_filename):

            overwrite_result_query = "ksc-result.txt already exists. " \
                    "Overwrite? [y/N]: "
            overwrite = query_user_bool(overwrite_result_query)

            if overwrite.lower() != 'y':
                print("Unable to get an explicit overwrite acknowledgement. "
                        "Quitting.")
                sys.exit(1)

        if os.path.isfile(output_filename):
            with open(output_filename, 'w+') as f:
                f.truncate()

        try:
            with open(output_filename, "a") as f:
                command = "[command: %s]\n" % " ".join(sys.argv)

                f.write(command)
                for ko_file in self.all_symbols_used:
                    ns = list(filter(lambda x: x, self.import_ns[ko_file]))
                    if ns:
                        ns = "@ns:" + "@ns:".join(ns)
                    else:
                        ns = ""
                    f.write("\n{%s@%s%s}\n\n" % (
                        os.path.basename(ko_file),
                        self.vermagic[ko_file].strip(),
                        ns
                    ))
                    self.write_result(f, ko_file)

            if not self.mock:
                print("A copy of the report is saved in %s" % output_filename)

        except Exception as e:
            print("Error in saving the result file at %s" % output_filename)
            print(e)
            sys.exit(1)

    def print_result(self, kmod_path):
        """
        Print the result (score)
        """

        print("Processing %s" % kmod_path)

        for name in self.nonstable_symbols_used[kmod_path]:
            if name not in self.total:
                print("WARNING: External symbol in %s does not "
                      "exist in current kernel: %s" \
                      % (os.path.basename(kmod_path),name))

        total_len = len(self.all_symbols_used[kmod_path])
        non_stable = len(self.nonstable_symbols_used[kmod_path])
        stable_len = float(len(self.stable_symbols[kmod_path]))

        if total_len == 0:  # pragma: no cover
            print("No kernel symbol usage found in %s." % kmod_path)
            return

        score = (stable_len / total_len) * 100

        if not self.mock:
            print("Checking against architecture %s" % self.arch)
            print("Total symbol usage: %s\t"
                  "Total Non stable list symbol usage: %s"
                  % (total_len, non_stable))
            print("Score: %0.2f%%\n" % score)

    def find_arch(self, kmod_list):
        """
        Finds the architecture of the file in given path
        """
        rset = {'littleendianIntel80386': 'i686',
                'bigendianPowerPC64': 'ppc64',
                'littleendianPowerPC64': 'ppc64le',
                'littleendianAdvancedMicroDevicesX86-64': 'x86_64',
                'bigendianIBMS/390': 's390x',
                'littleendianAArch64': 'aarch64'}
        arch = []
        for kmod_path in kmod_list:
            try:
                data = run("readelf -h %s | grep -e Data -e Machine | awk -F "
                        "':' '{print $2}' | paste -d ' '  - - | awk -F ',' "
                        "'{print $2}' | sed 's/[ \t]*//g'" % kmod_path)
                arch.append(rset[data.strip()])
            except IOError as e:
                print(e, end=' ')
                print(("(Only kernel object files are supported)")
                    if "No such file" not in str(e)
                    else "")
                sys.exit(1)
            except KeyError:
                print("%s: Invalid architecture. (only %s are supported)"
                    % (kmod_path, ', '.join(sorted(rset.values()))))
                sys.exit(1)

        arch = list(set(arch))
        if len(arch) > 1:
            print("Object files for multiple architectures were provided (%s)."
                % ', '.join(sorted(arch)))
            sys.exit(1)

        self.arch = arch[0]

    def write_result(self, f, ko_file):
        """
        Save the result set in the given file
        """
        try:
            ko_basename = os.path.basename(ko_file)

            f.write("[%s]\n" % self.arch)

            # Write stablelisted symbols
            f.write(self.SECTION_STABLELISTS)
            for name in sorted(self.stable_symbols[ko_file]):
                f.write(name + '\n')

            # Write non-stablelisted symbols as well as their justification
            # Justification can be one of:
            #  - free-form entry
            #  - reference to a different kernel module section (if exists)
            #  - justification placeholder later to be specified by hand
            f.write(self.SECTION_CO_STABLELISTS)
            for name in sorted(self.nonstable_symbols_used[ko_file]):

                justification=""
                if name in self.justified_symbols \
                        and ko_basename != self.justified_symbols[name]:
                    justification=self.JUSTIFICATION_REFERENCE % \
                            self.justified_symbols[name]
                elif ko_basename in self.justifications and \
                        name in self.justifications[ko_basename]:
                    justification=self.justifications[ko_basename][name]
                elif "" in self.justifications and \
                        name in self.justifications[ko_basename]:
                    justification=self.justifications[ko_basename][name]
                else:
                    justification=self.JUSTIFICATION_PLACEHOLDER
                    self.justified_symbols[name] = os.path.basename(ko_file)

                f.write(self.JUSTIFICATION_SEPARATOR)
                f.write(self.JUSTIFICATION_BODY % (name, justification))

            if self.nonstable_symbols_used[ko_file]:
                f.write(self.JUSTIFICATION_SEPARATOR)
                f.write('\n')
        except Exception as err:
            print(err)

    def read_data(self, arch, releasedir, symvers):
        """
        Read both data files
        """
        self.matchdata, exists = read_list(arch, releasedir, self.verbose)
        self.total = read_total_list(symvers)
        return exists

    def parse_ko(self, path, process_stablelists=True):
        """
        parse a ko file
        """
        if process_stablelists:
            self.nonstable_symbols_used[path] = set()
            self.all_symbols_used[path] = set()
            self.nonstable_symbols_used[path] = set()
            self.stable_symbols[path] = set()

        self.defined_symbols[path] = set()

        try:
            self.vermagic[path] = run("modinfo -F vermagic '%s'" % path)
        except Exception as e:
            print(e)
            sys.exit(1)

        try:
            self.import_ns[path] = run("modinfo -F import_ns '%s'" % path).split('\n')
        except Exception as e:
            print(e)
            sys.exit(1)

        try:
            out = run("nm '%s'" % path)
        except Exception as e:
            print(e)
            sys.exit(1)

        for line in out.split("\n"):
            data = line.split(" ")
            if len(data) < 2:
                continue
            if "U " in line and process_stablelists:
                self.find_if(path, data[len(data)-1])
            else:
                self.defined_symbols[path].add(data[len(data)-1])

    def remove_internal_symbols(self):
        for i in self.nonstable_symbols_used:
            for j in self.defined_symbols:
                if i == j:
                    continue
                self.nonstable_symbols_used[i] -= self.defined_symbols[j]

    def find_if(self, path, name):
        """
        Find if the symbol is in stablelist or not
        """
        self.all_symbols_used[path].add(name)
        if name in self.matchdata:
            self.stable_symbols[path].add(name)
        else:
            self.nonstable_symbols_used[path].add(name)

    def get_module_name(self, command_line):
        try:
            match = self.HEADER_RE.match(command_line)
            if not match:
                return None
            commands = match.group("cmd").split()

            # Ignore undefined options in parser instead of throwing error
            class IOptParse(OptionParser):
                def error(self, msg):
                    pass

            parser = IOptParse()
            parser.add_option("-k", "--ko")
            opts, _ = parser.parse_args(commands[0:])
            return opts.ko
        except Exception:
            return None


if __name__ == '__main__':
    k = Ksc()
    k.main()
    sys.exit(0)
