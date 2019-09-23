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

import os
import time

from fuzzer.communicator import recv_msg, Communicator
from threading import Thread
from common.config import FuzzerConfiguration
from common.debug import log_update
from common.ui import *
from common.evaluation import Evaluation

__author__ = 'Sergej Schumilo'


def update_loader(comm):
    log_update("PID: " + str(os.getpid()))
    slave_process = UpdateProcess(comm)
    try:
        slave_process.loop()
    except KeyboardInterrupt:
        log_update("Exiting...")

class UpdateProcess:
    def __init__(self, comm):
        self.comm = comm
        self.config = FuzzerConfiguration()
        self.timeout = self.config.config_values['UI_REFRESH_RATE']


    def blacklist_updater(self, ui):
        while True:
            try:
                counter = 0
                with open("/dev/shm/kafl_filter0", "rb") as f:
                    while True:
                        byte = f.read(1)
                        if not byte:
                            break
                        if byte != '\x00':
                            counter += 1
                ui.blacklist_counter = counter

                counter = 0
                with open("/dev/shm/kafl_tfilter", "rb") as f:
                    while True:
                        byte = f.read(1)
                        if not byte:
                            break
                        if byte != '\x00':
                            counter += 1
                ui.blacklist_tcounter = counter

            except:
                pass
            time.sleep(2)

    def loop(self, eval_time_threshold=1.0):
        ui = FuzzerUI(self.comm.num_processes, fancy=self.config.argument_values['f'], inline_log=self.config.argument_values['l'], redqueen=self.config.argument_values['r'])
        ev = Evaluation(self.config)
        ui.install_sighandler()
        Thread(target=self.blacklist_updater, args=(ui,)).start()
        update = None
        counter = 0
        while True:
            start = time.time()
            while (time.time()-start < eval_time_threshold):
                ui.refresh()
                time.sleep(self.timeout)
                ev.write_data(ui.blacklist_counter)
