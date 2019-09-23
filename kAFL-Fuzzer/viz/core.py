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

import mmh3
import time
import os
from sys import stdout
from common.config import VizConfiguration
from common.qemu import qemu
from common.debug import log_info, enable_logging
from common.self_check import post_self_check
from threading import Thread

import common.color
from random import randint
import os.path

__author__ = 'Sergej Schumilo'


def start():
    config = VizConfiguration()

    if(config.argument_values['mode'] == "dot"):
    	while True:
    		if os.path.isfile(config.argument_values['work_dir'] + "/graph.dot"):
    			break
    		time.sleep(0.25)
        os.system("xdot " + config.argument_values['work_dir'] + "/graph.dot 2> /dev/null")
    elif(config.argument_values['mode'] == "plot"):
    	while True:
    		if os.path.isfile(config.argument_values['work_dir'] + "/graph.dot"):
    			break
    		time.sleep(0.25)
        os.system("cd " + config.argument_values['work_dir'] + "/evaluation/ ;" + " gnuplot plot.gnu > /dev/null 2> /dev/null")
   
    return 0
