# Copyright 2013 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import functools
import uuid

from oslo_config import cfg
from oslo_log import log
import six

from sidserver.common import authorization
from sidserver.common import dependency
from sidserver.common import utils
from sidserver.common import wsgi
from sidserver import exception
from sidserver.i18n import _, _LW


LOG = log.getLogger(__name__)
CONF = cfg.CONF


def v2_deprecated(f):
    """No-op decorator in preparation for deprecating Identity API v2.

    This is a placeholder for the pending deprecation of v2. The implementation
    of this decorator can be replaced with::

        from sidserver.openstack.common import versionutils


        v2_deprecated = versionutils.deprecated(
            what='v2 API',
            as_of=versionutils.deprecated.JUNO,
            in_favor_of='v3 API')

    """
    return f


def filterprotected(*filters):
    """Wraps filtered API calls with role based access controls (RBAC)."""

    def _filterprotected(f):
        @functools.wraps(f)
        def wrapper(self, context, **kwargs):
            if not context['is_admin']:
                action = 'identity:%s' % f.__name__
                # Now, build the target dict for policy check.  We include:
                #
                # - Any query filter parameters
                # - Data from the main url (which will be in the kwargs
                #   parameter) and would typically include the prime key
                #   of a get/update/delete call
                #
                # First  any query filter parameters
                target = dict()
                if filters:
                    for item in filters:
                        if item in context['query_string']:
                            target[item] = context['query_string'][item]

                    LOG.debug('RBAC: Adding query filter params (%s)', (
                        ', '.join(['%s=%s' % (item, target[item])
                                  for item in target])))

                # Now any formal url parameters
                for key in kwargs:
                    target[key] = kwargs[key]

                self.policy_api.enforce(creds,
                                        action,
                                        utils.flatten_dict(target))

                LOG.debug('RBAC: Authorization granted')
            else:
                LOG.warning(_LW('RBAC: Bypassing authorization'))
            return f(self, context, filters, **kwargs)
        return wrapper
    return _filterprotected

