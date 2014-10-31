#!/usr/bin/env python3
# Copyright (c) 2014 Brainly.com sp. z o.o.
# Copyright (c) 2013 Spotify AB
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

# Global imports:
import mock
import os
import subprocess
import sys
import unittest

# To perform local imports first we need to fix PYTHONPATH:
pwd = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.abspath(pwd + '/../../modules/'))

# Local imports:
import file_paths as paths
import check_zonesync

class TestCheckZoneSync(unittest.TestCase):

    # Used by side effects:
    @staticmethod
    def _terminate_script(*unused):
        raise SystemExit(0)

    # Fake configuration data factory:
    def _script_conf_factory(self, **kwargs):
        good_configuration = {"lockfile": paths.TEST_LOCKFILE,
                              "history_file": paths.TEST_STATUSFILE,
                              }

        def func(key):
            config = good_configuration.copy()
            config.update(kwargs)
            self.assertIn(key, config)
            return config[key]

        return func



if __name__ == '__main__':
    unittest.main()
