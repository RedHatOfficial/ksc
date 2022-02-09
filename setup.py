from setuptools import setup, find_packages
import pathlib

from distutils.core import Command
from unittest import TextTestRunner, TestLoader
import os

bugzilla = []
for x in os.listdir('bugzilla/'):
    bugzilla.append('bugzilla/%s' % x)

setup(name='ksc',
      version='1.9',
      description="ksc tool",
      long_description="Kernel Module Source Checker tool",
      url='https://github.com/RedHatOfficial/ksc/',
      platforms=["Linux"],
      classifiers= [
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'Topic :: Software Development :: Build Tools',
          'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
          'Programming Language :: Python :: 3'
      ],
      python_requires='>=3.6, <4',
      install_requires=[
          'requests'
      ],
      author="Kushal Das, Samikshan Bairagya, Stanislav Kozina, Martin Lacko, Ziqian Sun",
      author_email="kdas@redhat.com, sbairagy@redhat.com, skozina@redhat.com, mlacko@redhat.com, zsun@redhat.com",
      license="http://www.gnu.org/copyleft/gpl.html",
      data_files=[("/usr/bin", ['ksc']),
                  ('/etc', ['data/ksc.conf']),
                  ('/usr/share/ksc', ['ksc.py', 'utils.py']),
                  ('/usr/share/ksc/data', ['data/ksc.conf']),
                  ('/usr/share/ksc/bugzilla', bugzilla)])
