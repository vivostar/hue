#!/usr/bin/env python
# Licensed to Cloudera, Inc. under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  Cloudera, Inc. licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import glob
import logging
from posixpath import curdir, join, pardir, sep

# The root of the Hue installation
INSTALL_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..', '..'))

# The apps location
APPS_ROOT = os.path.join(INSTALL_ROOT, 'apps')

# Directory holding app.reg
HUE_APP_REG_DIR = os.environ.get("HUE_APP_REG_DIR", INSTALL_ROOT)

# Directory holding hue.pth
HUE_PTH_DIR = os.environ.get('HUE_PTH_DIR', None)

# The Hue config directory
HUE_CONF_DIR = os.path.join(INSTALL_ROOT, 'desktop', 'conf')

# The Python executable in virtualenv
ENV_PYTHON = os.environ.get("ENV_PYTHON")

PYTHON_VER = os.environ.get("PYTHON_VER", "")

# Virtual env
VIRTUAL_ENV = os.environ.get("VIRTUAL_ENV")


def cmp_version(ver1, ver2):
  """Compare two version strings in the form of 1.2.34"""
  return cmp([int(v) for v in ver1.split('.')], [int(v) for v in ver2.split('.')])


def _get_python_lib_dir():
  glob_path = os.path.join(VIRTUAL_ENV, 'lib', 'python*')
  res = glob.glob(glob_path)
  if len(res) == 0:
    raise SystemError("Cannot find a Python installation in %s. "
                      "Did you do `make hue'?" % glob_path)
  elif len(res) > 1:
    raise SystemError("Found multiple Python installations in %s. "
                      "Please `make clean' first." % glob_path)
  return res[0]


def _get_python_site_packages_dir():
  return os.path.join(_get_python_lib_dir(), 'site-packages')


def cmp(x, y):
  """
  Replacement for built-in function cmp that was removed in Python 3

  Compare the two objects x and y and return an integer according to
  the outcome. The return value is negative if x < y, zero if x == y
  and strictly positive if x > y.
  """

  return (x > y) - (x < y)
