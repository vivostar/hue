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
import logging
import sys

from desktop.conf import default_ssl_validate, has_connectors
from desktop.lib.conf import Config, UnspecifiedConfigSection, ConfigSection, coerce_bool

if sys.version_info[0] > 2:
  from django.utils.translation import gettext_lazy as _t
else:
  from django.utils.translation import ugettext_lazy as _t


LOG = logging.getLogger(__name__)


def is_ozone_enabled():
  if has_connectors():
    from desktop.lib.connectors.api import _get_installed_connectors
    return any([connector for connector in _get_installed_connectors() if connector['dialect'] == 'ozone'])
  else:
    return list(OZONE_CLUSTERS.keys())


def get_ozone_conf_dir_default():
  """
  Get from environment variable OZONE_CONF_DIR or '/etc/ozone/conf'
  """
  return os.environ.get("HADOOP_CONF_DIR", "/etc/hadoop/conf")

UPLOAD_CHUNK_SIZE = Config(
  key="upload_chunk_size",
  help="Size, in bytes, of the 'chunks' Django should store into memory and feed into the handler. Default is 64MB.",
  type=int,
  default=1024 * 1024 * 64)

OZONE_CLUSTERS = UnspecifiedConfigSection(
  "ozone_clusters",
  help="One entry for each Ozone cluster",
  each=ConfigSection(
    help="Information about a single Ozone cluster",
    members=dict(
      FS_DEFAULTFS=Config(
          "fs_defaultfs",
          help="The equivalent of fs.defaultFS (aka fs.default.name)",
          type=str,
          default="ofs://localhost:8020"
      ),
      LOGICAL_NAME=Config(
          "logical_name",
          default="",
          type=str,
          help=_t('NameNode logical name.')
      ),
      WEBHDFS_URL=Config(
          "webhdfs_url",
          help="The URL to WebHDFS/HttpFS service. Defaults to the WebHDFS URL on the NameNode.",
          type=str,
          default="http://localhost:50070/webhdfs/v1"
      ),
      SECURITY_ENABLED=Config(
          "security_enabled",
          help="Whether Ozone requires client to perform Kerberos authentication",
          type=coerce_bool,
          default=False
      ),
      SSL_CERT_CA_VERIFY=Config(
          "ssl_cert_ca_verify",
          help="Choose whether Hue should validate certificates received from the server.",
          dynamic_default=default_ssl_validate,
          type=coerce_bool
      ),
      TEMP_DIR=Config(
          "temp_dir",
          help="Ozone directory for temporary files",
          default='/tmp',
          type=str
      ),
      OZONE_CONF_DIR=Config(
          key="ozone_conf_dir",
          dynamic_default=get_ozone_conf_dir_default,
          help="Directory of the Ozone configuration. Defaults to the env variable OZONE_CONF_DIR when set, or '/etc/ozone/conf'",
          type=str
      ),
    )
  )
)

# def config_validator(user):
#   """
#   config_validator() -> [ (config_variable, error_message) ]

#   Called by core check_config() view.
#   """
#   from hadoop.fs import webhdfs

#   res = []

#   # HDFS_CLUSTERS
#   has_default = False
#   for name in list(HDFS_CLUSTERS.keys()):
#     cluster = HDFS_CLUSTERS[name]
#     res.extend(webhdfs.test_fs_configuration(cluster))
#     if name == 'default':
#       has_default = True
#   if HDFS_CLUSTERS.keys() and not has_default:
#     res.append(("hadoop.hdfs_clusters", "You should have an HDFS called 'default'."))

#   return res