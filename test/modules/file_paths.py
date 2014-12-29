#!/usr/bin/env python3
# Copyright (c) 2014 Brainly.com sp. z o.o.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

import os.path as op

#Where am I ?
_module_dir = op.dirname(op.realpath(__file__))
_main_dir = op.abspath(op.join(_module_dir, '..'))
_fabric_base_dir = op.join(_main_dir, 'fabric/')

#Configfile location
TEST_CONFIG_FILE = op.join(_fabric_base_dir, 'check-zonesync.yml')
TEST_NOZONEFILE_CONFIG_FILE = op.join(_fabric_base_dir, 'check-zonesync-nozonefile.yml')
TEST_ZONE_BAD = op.join(_fabric_base_dir, 'localdomain-bad.zone')
TEST_ZONE_GOOD = op.join(_fabric_base_dir, 'localdomain-good.zone')
TEST_ZONE_GOOD_SOA_DIFFERS = op.join(_fabric_base_dir, 'localdomain-good-soa-differs.zone')
TEST_ZONE_GOOD_ADDED_RECORD = op.join(_fabric_base_dir, 'localdomain-good-added-record.zone')
TEST_ZONE_GOOD_DELETED_RECORD = op.join(_fabric_base_dir, 'localdomain-good-deleted-record.zone')
TEST_ZONE_GOOD_CHANGED_RECORD = op.join(_fabric_base_dir, 'localdomain-good-changed-record.zone')

#Test lockfile location:
TEST_LOCKFILE = op.join(_fabric_base_dir, 'filelock.pid')
