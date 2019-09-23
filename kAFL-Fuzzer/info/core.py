"""
This file is part of the Redqueen fuzzer.

Sergej Schumilo, 2019 <sergej@schumilo.de> 
Cornelius Aschermann, 2019 <cornelius.aschermann@rub.de> 

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with Redqueen.  If not, see <http://www.gnu.org/licenses/>. 
"""

import time
import os
from common.config import InfoConfiguration
from common.qemu import qemu
from common.debug import log_info, enable_logging
from common.self_check import post_self_check

__author__ = 'Sergej Schumilo'

def start():
    config = InfoConfiguration()

    if not post_self_check(config):
        return -1

    if config.argument_values['v']:
        enable_logging()

    log_info("Dumping target addresses...")
    if os.path.exists("/tmp/kAFL_info.txt"):
        os.remove("/tmp/kAFL_info.txt")
    q = qemu(0, config)
    q.start()
    q.__del__()
    try:
        for line in open("/tmp/kAFL_info.txt"):
            print line,
        os.remove("/tmp/kAFL_info.txt")
    except:
        pass
    return 0
