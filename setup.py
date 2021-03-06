#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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


from setuptools import setup

setup(name='check_zonesync',
      version='1',
      author='Pawel Rozlach',
      author_email='pawel.rozlach@brainly.com',
      license='ASF2.0',
      url='https://github.com/brainly/check_zonesync',
      description='Zone replication synchronization check',
      packages=['check_zonesync'],
      scripts=['bin/check-zonesync'],
    )
