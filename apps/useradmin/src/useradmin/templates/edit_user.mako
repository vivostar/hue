## Licensed to Cloudera, Inc. under one
## or more contributor license agreements.  See the NOTICE file
## distributed with this work for additional information
## regarding copyright ownership.  Cloudera, Inc. licenses this file
## to you under the Apache License, Version 2.0 (the
## "License"); you may not use this file except in compliance
## with the License.  You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
<%!
import sys

from desktop.auth.backend import is_admin, is_hue_admin
from desktop.conf import ENABLE_ORGANIZATIONS, ENABLE_CONNECTORS
from desktop.views import commonheader, commonfooter

from useradmin.hue_password_policy import is_password_policy_enabled, get_password_hint
from useradmin.views import is_user_locked_out

if sys.version_info[0] > 2:
  from django.utils.translation import gettext as _
else:
  from django.utils.translation import ugettext as _
%>

<%namespace name="layout" file="layout.mako" />

% if not is_embeddable:
  ${ commonheader(_('Users'), "useradmin", user, request) | n,unicode }
% endif

${ layout.menubar(section='users') }


<div id="editUserComponents" class="useradmin container-fluid">
  <div class="card card-small title">
    <h1 class="card-heading simple">
      ${ _('User %(username)s') % dict(username=username) if username else _('Create user') }
      % if ENABLE_ORGANIZATIONS.get():
        @ ${ user.organization }
      % endif
    </h1>

    <br/>

    <form id="editForm" method="POST" class="form form-horizontal" autocomplete="off">
    ${ csrf_token(request) | n,unicode }
    <div id="properties" class="section">
      <ul class="nav nav-tabs" style="margin-bottom: 0">
        <li class="active">
          <a href="javascript:void(0)" class="step" data-step="step1">${ _('Step 1: Credentials') }
          % if not username:
            ${ _('(required)') }
          % endif
          </a>
        </li>
        <li><a href="javascript:void(0)" class="step" data-step="step2">${ is_admin(user) and _('Step 2: Profile and Groups') or _('Step 2: Profile') }</a>
        </li>
        % if is_admin(user):
          <li><a href="javascript:void(0)" class="step" data-step="step3">${ _('Step 3: Advanced') }</a></li>
        % endif
      </ul>

    <div class="steps">
      <div id="step1" class="stepDetails">
        % if ENABLE_ORGANIZATIONS.get():
          ${ layout.render_field(form["email"], extra_attrs={'validate':'true'}) }
        % else:
          ${ layout.render_field(form["username"], extra_attrs={'validate':'true'}) }
        % endif

        % if "password1" in form.fields:
          % if username and "password_old" in form.fields:
            ${ layout.render_field(form["password_old"], extra_attrs=username is None and {'validate':'true'} or {}) }
          % endif
          ${ layout.render_field(form["password1"], extra_attrs=username is None and {'validate':'true'} or {}) }
          % if is_password_policy_enabled():
            <div class="password_rule" style="margin-left:180px; width:500px;">
              <p>${ get_password_hint() }</p>
            </div>
          % endif
          ${layout.render_field(form["password2"], extra_attrs=username is None and {'validate':'true'} or {})}
        % endif

        % if not ENABLE_CONNECTORS.get():
          ${ layout.render_field(form["ensure_home_directory"]) }
        % endif
        </div>

        <div id="step2" class="stepDetails hide">
          % if "first_name" in form.fields:
            ${layout.render_field(form["first_name"])}
            ${layout.render_field(form["last_name"])}
          % endif

          % if ENABLE_ORGANIZATIONS.get():
            ${layout.render_field(form["organization"])}
          % else:
            ${layout.render_field(form["email"])}
          % endif

          % if request.user.username == username:
            ${layout.render_field(form["language"])}
          % endif

          % if is_admin(user):
            ${layout.render_field(form["groups"])}
          % endif
        </div>
        % if is_admin(user):
          <div id="step3" class="stepDetails hide">
            ${ layout.render_field(form["is_active"]) }

            % if is_hue_admin(user):
              ${ 'is_superuser' in form.fields and layout.render_field(form["is_superuser"]) }
            % endif

            % if is_user_locked_out(username):
              ${ layout.render_field(form["unlock_account"]) }
            % endif
          </div>
        % endif
      </div>

      <div class="form-actions">
        <a class="backBtn btn disabled">${ _('Back') }</a>
        <a class="nextBtn btn btn-primary disable-feedback">${ _('Next') }</a>
        % if is_embeddable:
          <input type="hidden" value="true" name="is_embeddable" />
        % endif
        % if username:
        <input type="submit" class="btn btn-primary disable-feedback" value="${_('Update user')}"/>
        % else:
        <input type="submit" class="btn btn-primary disable-feedback" value="${_('Add user')}"/>
        % endif
      </div>
    </form>
  </div>
</div>

<script src="${ static('desktop/js/edit_users-inline.js') }" type="text/javascript"></script>

${layout.commons()}

%if not is_embeddable:
${ commonfooter(None, messages) | n,unicode }
%endif
