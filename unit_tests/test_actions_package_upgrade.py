# Copyright 2022 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest.mock import patch
import os

os.environ['JUJU_UNIT_NAME'] = 'nova_compute'

with patch('charmhelpers.core.hookenv.config') as config:
    config.return_value = 'nova'
    with patch('charmhelpers.contrib.openstack.context.HostInfoContext'):
        import nova_compute_utils as utils  # noqa

with patch('nova_compute_utils.restart_map'):
    with patch('nova_compute_utils.register_configs'):
        import package_upgrade

from test_utils import (
    CharmTestCase
)

TO_PATCH = [
    'config_changed',
    'do_openstack_upgrade'
]


class TestNovaComputeUpgradeActions(CharmTestCase):

    def setUp(self):
        super(TestNovaComputeUpgradeActions, self).setUp(package_upgrade,
                                                         TO_PATCH)

    @patch.object(package_upgrade, 'relation_ids')
    @patch('charmhelpers.contrib.openstack.utils.action_set')
    @patch('charmhelpers.contrib.openstack.utils.openstack_upgrade_available')
    @patch('charmhelpers.contrib.openstack.utils.juju_log')
    def test_package_upgrade_success(self, log, upgrade_avail,
                                     action_set, relation_ids):
        upgrade_avail.return_value = False
        package_upgrade.package_upgrade()
        self.assertTrue(self.do_openstack_upgrade.called)

    @patch.object(package_upgrade, 'relation_ids')
    @patch('charmhelpers.contrib.openstack.utils.action_set')
    @patch('charmhelpers.contrib.openstack.utils.openstack_upgrade_available')
    @patch('charmhelpers.contrib.openstack.utils.juju_log')
    def test_openstack_upgrade_failure(self, log, upgrade_avail,
                                       action_set, relation_ids):
        upgrade_avail.return_value = True
        package_upgrade.package_upgrade()
        self.assertFalse(self.do_openstack_upgrade.called)
