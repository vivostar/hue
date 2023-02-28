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

"""
Interfaces for Hadoop filesystem access via HttpFs/WebHDFS
"""
import logging
import threading

from desktop.lib.rest import http_client, resource
from desktop.lib.fs.ozone import OFS_ROOT, normpath, is_root, parent_path
from desktop.lib.fs.ozone.ofsstat import OzoneFSStat

from hadoop.fs.exceptions import WebHdfsException
from hadoop.hdfs_site import get_umask_mode
from hadoop.fs.webhdfs import WebHdfs


LOG = logging.getLogger(__name__)


def get_ofs_home_directory():
  return OFS_ROOT


class OzoneFS(WebHdfs):
  """
  OzoneFS implements the filesystem interface via the WebHDFS/HttpFS REST protocol.
  """
  def __init__(
      self,
      url,
      fs_defaultfs,
      logical_name=None,
      security_enabled=False,
      ssl_cert_ca_verify=True,
      temp_dir="/tmp",
      umask=0o1022,
      ):
    self._url = url
    self._security_enabled = security_enabled
    self._ssl_cert_ca_verify = ssl_cert_ca_verify
    self._temp_dir = temp_dir
    self._fs_defaultfs = fs_defaultfs
    self._logical_name = logical_name
    self.expiration = None
    self._umask = umask
    self._scheme = "ofs://"
    self._is_remote = True

    self._client = self._make_client(url, security_enabled, ssl_cert_ca_verify)
    self._root = resource.Resource(self._client)

    self._thread_local = threading.local()

  @classmethod
  def from_config(cls, ofs_config):
    return cls(
        url=ofs_config.WEBHDFS_URL.get(),
        fs_defaultfs=ofs_config.FS_DEFAULTFS.get(),
        logical_name=ofs_config.LOGICAL_NAME.get(),
        security_enabled=ofs_config.SECURITY_ENABLED.get(),
        ssl_cert_ca_verify=ofs_config.SSL_CERT_CA_VERIFY.get(),
        temp_dir=ofs_config.TEMP_DIR.get(),
        umask=get_umask_mode(),
    )

  def strip_normpath(self, path):
    if path.startswith('ofs://'):
      path = path[5:]
    if path.startswith('ofs:/'):   ## when filechooser opens it is giving ofs:/path
      path = path[4:]              ## need to check why
    return path

  def normpath(self, path):
    return normpath(path)

  def netnormpath(self, path):
    return normpath(path)

  def isroot(self, path):
    return is_root(path)

  def parent_path(self, path):
    return parent_path(path)

  def listdir_stats(self, path, glob=None):
    """
    listdir_stats(path, glob=None) -> [ OzoneFSStat ]

    Get directory listing with stats.
    """
    path = self.strip_normpath(path)
    params = self._getparams()
    if glob is not None:
      params['filter'] = glob
    params['op'] = 'LISTSTATUS'
    headers = self._getheaders()
    json = self._root.get(path, params, headers)
    filestatus_list = json['FileStatuses']['FileStatus']
    return [OzoneFSStat(st, path) for st in filestatus_list]

  def _stats(self, path):
    """
    This version of stats returns None if the entry is not found.
    """
    path = self.strip_normpath(path)
    params = self._getparams()
    params['op'] = 'GETFILESTATUS'
    headers = self._getheaders()
    try:
      json = self._root.get(path, params, headers)
      return OzoneFSStat(json['FileStatus'], path)
    except WebHdfsException as ex:
      if ex.server_exc == 'FileNotFoundException' or ex.code == 404:
        return None
      raise ex
  
  def stats(self, path):
    """
    stats(path) -> OzoneFSStat
    """
    res = self._stats(path)
    if res is not None:
      return res
    raise IOError(errno.ENOENT, _("File %s not found") % path)
