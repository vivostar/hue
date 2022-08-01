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
#
# Tests for Help

import sys
import logging
from nose.plugins.skip import SkipTest
from nose.tools import assert_true, assert_equal

from desktop.lib.django_test_util import make_logged_in_client
LOG = logging.getLogger(__name__)

def test_about():
  c = make_logged_in_client(username="test", is_superuser=True)

  # Test default output
  response = c.get('/help/')
  i = 100000
  LOG.info("response content first %d chars %s" % (i, response.content[0:i]))
  LOG.info("log type of %s" % (type(response.content)))
  assert_true(b'Introducing Hue' in response.content)

  # Test default to index.md
  response = c.get("/help/about/")
  response2 = c.get("/help/about/index.html")
  assert_equal(response.content, response2.content)

  # Test index at the bottom
  assert_true(b'href="/help/desktop' in response.content)
