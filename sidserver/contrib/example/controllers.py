# Copyright 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


from sidserver.common import controller
from sidserver.common import dependency


@dependency.requires('example_api')
class ExampleV3Controller(controller.V3Controller):

    @controller.protected()
    def example_get(self, context):
        """Description of the controller logic."""
        self.example_api.do_something(context)