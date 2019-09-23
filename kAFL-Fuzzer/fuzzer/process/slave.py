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

import os, signal, sys
import time
import mmh3
import struct
import subprocess
from fuzzer.communicator import send_msg, recv_msg
from fuzzer.protocol import *
from fuzzer.technique.redqueen.hash_fix import HashFixer
from fuzzer.state import RedqueenState
from common.config import FuzzerConfiguration
from common.qemu import qemu
from common.debug import log_slave, log_redq, configure_log_prefix

from fuzzer.technique.trim import perform_trim

import traceback
__author__ = 'Sergej Schumilo'

def slave_loader(comm, slave_id):
    log_slave("PID: " + str(os.getpid()), slave_id)

    slave_process = SlaveProcess(comm, slave_id)
    try:
        slave_process.loop()
    except KeyboardInterrupt:
        comm.slave_termination.value = True
    log_slave("Killed!", slave_id)


class SlaveProcess:

    def __init__(self, comm, slave_id, auto_reload=False):
        self.config = FuzzerConfiguration()
        self.redqueen_state = RedqueenState() #globally shared redqueen state
        self.comm = comm
        self.slave_id = slave_id
        self.counter = 0
        self.q = qemu(self.slave_id, self.config)
        self.false_positiv_map = set()
        self.stage_tick_treshold = 0
        self.timeout_tick_factor = self.config.config_values["TIMEOUT_TICK_FACTOR"]
        self.auto_reload = auto_reload
        self.soft_reload_counter = 0
        configure_log_prefix("%.2d"%slave_id)

    def __restart_vm(self):
        return True
        if self.comm.slave_termination.value:
            return False
        self.comm.reload_semaphore.acquire()
        try:
            if self.soft_reload_counter >= 32:
                self.soft_reload_counter = 0
                raise Exception("...")
            self.q.soft_reload()
            self.soft_reload_counter += 1
        except:
            log_slave("restart failed %s"%traceback.format_exc(), self.slave_id)
            while True:
                self.q.__del__()
                self.q = qemu(self.slave_id, self.config)
                if self.q.start():
                    break
                else:
                    time.sleep(0.5)
                    log_slave("Fail Reload", self.slave_id)
        self.comm.reload_semaphore.release()
        self.q.set_tick_timeout_treshold(self.stage_tick_treshold * self.timeout_tick_factor)
        if self.comm.slave_termination.value:
            return False
        return True

    def __respond_job_req(self, response):
        results = []
        performance = 0.0
        counter = 0

        jobs = response.data[0]
        methods = response.data[1]

        self.q.get_bb_delta()

        self.comm.slave_locks_A[self.slave_id].acquire()
        if self.comm.effector_mode.value:
            effector_mode_hash = (self.comm.effector_mode_hash_a.value, self.comm.effector_mode_hash_b.value)
        else:
            effector_mode_hash = None
        for i in range(len(jobs)):
            if not self.comm.stage_abortion_notifier.value:
                new_bits = True
                vm_reloaded = False
                self.reloaded = False
                bitmap = ""
                payload = ""
                payload_size = 0
                if self.comm.slave_termination.value:
                    self.comm.slave_locks_B[self.slave_id].release()
                    send_msg(KAFL_TAG_RESULT, results, self.comm.to_mapserver_queue, source=self.slave_id)
                    return 
                while True:
                    while True:
                        try:
                            payload, payload_size = self.q.copy_master_payload(self.comm.get_master_payload_shm(self.slave_id), i,
                                                       self.comm.get_master_payload_shm_size())

                            start_time = time.time()
                            bitmap = self.q.send_payload()
                            performance = time.time() - start_time

                            methods[i].bb_delta = self.q.get_bb_delta()
                            if methods[i].bb_delta != 0:
                                log_slave("FML", self.slave_id)

                            break
                        except Exception as e: 
                            log_slave(str(e), self.slave_id)
                            log_slave("%s"%traceback.format_exc(), self.slave_id)
                            if not self.__restart_vm():
                                return
                            self.reloaded = True
                    if not bitmap:
                        log_slave("SHM ERROR....", self.slave_id)
                        if not self.__restart_vm():
                            self.comm.slave_locks_B[self.slave_id].release()
                            send_msg(KAFL_TAG_RESULT, results, self.comm.to_mapserver_queue, source=self.slave_id)
                            return
                    else:
                        break
                
                new_bits = self.q.copy_bitmap(self.comm.get_bitmap_shm(self.slave_id), i, self.comm.get_bitmap_shm_size(), bitmap, payload, payload_size, effector_mode_hash=effector_mode_hash)
                if new_bits:
                    self.q.copy_mapserver_payload(self.comm.get_mapserver_payload_shm(self.slave_id), i, self.comm.get_mapserver_payload_shm_size())
                results.append(FuzzingResult(i, self.q.crashed, self.q.timeout, self.q.kasan, jobs[i],
                                             self.slave_id, performance, methods[i], mmh3.hash64(bitmap), reloaded=(self.q.timeout or self.q.crashed or self.q.kasan), new_bits=new_bits, qid=self.slave_id))
                
                self.soft_reload_counter += 1
                if self.soft_reload_counter >= 10000:
                    self.q.soft_reload()
                    self.soft_reload_counter = 0

            else:
                results.append(FuzzingResult(i, False, False, False, jobs[i], self.slave_id, 0.0, methods[i], None, reloaded=False, new_bits=False, qid=self.slave_id))

        if self.comm.slave_termination.value:
            self.comm.slave_locks_B[self.slave_id].release()
            send_msg(KAFL_TAG_RESULT, results, self.comm.to_mapserver_queue, source=self.slave_id)
            return 

        self.comm.slave_locks_B[self.slave_id].release()
        send_msg(KAFL_TAG_RESULT, results, self.comm.to_mapserver_queue, source=self.slave_id)


    def __check_filter_bitmaps(self):
        p = subprocess.Popen(["md5sum", "/dev/shm/kafl_filter0", "/dev/shm/kafl_tfilter"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return p.stdout.read()

    def __respond_sampling_req(self, response):
        payload = response.data[0]
        sampling_rate = response.data[1]

        self.stage_tick_treshold = 0
        sampling_counter = 0
        sampling_ticks = 0
        error_counter = 0

        round_checker = 0
        self.__restart_vm()
        self.q.set_payload(payload)

        filter_hash = self.__check_filter_bitmaps()

        while True:
            error = False
            while True:
                try:
                    self.q.enable_sampling_mode()
                    bitmap = self.q.send_payload()
                    break
                except:
                    log_slave("Sampling fail...", self.slave_id)
                    log_slave("%s"%traceback.format_exc(), self.slave_id)
                    if not self.__restart_vm():
                        return

            for i in range(5):
                try:

                    if error_counter >= 2:
                        log_slave("Abort sampling...", self.slave_id)
                        error = False
                        break

                    new_bitmap = self.q.send_payload()
                    if self.q.crashed or self.q.timeout or self.q.kasan:
                        log_slave("Sampling timeout...", self.slave_id)
                        error_counter += 1
                        if not self.__restart_vm():
                            error = False
                            break
                    else:
                        self.q.submit_sampling_run()
                        sampling_counter += 1
                        sampling_ticks = self.q.end_ticks - self.q.start_ticks

                except:
                    log_slave("Sampling wtf??!", self.slave_id)
                    log_slave("%s"%traceback.format_exc(), self.slave_id)
                    if not self.__restart_vm():
                        return

            while True:
                try:
                    self.q.disable_sampling_mode()
                    break
                except:
                    log_slave("%s"%traceback.format_exc(), self.slave_id)
                    if not self.__restart_vm():
                        return


            tmp_hash = self.__check_filter_bitmaps()
            if tmp_hash == filter_hash:
                round_checker += 1
            else:
                round_checker = 0

            filter_hash = tmp_hash
            if round_checker == 5:
                break

        log_slave("Sampling findished!", self.slave_id)
        
        if sampling_counter == 0:
            sampling_counter = 1
        self.stage_tick_treshold = sampling_ticks / sampling_counter
        log_slave("sampling_ticks: " + str(sampling_ticks), self.slave_id)
        log_slave("sampling_counter: " + str(sampling_counter), self.slave_id)
        log_slave("STAGE_TICK_TRESHOLD: " + str(self.stage_tick_treshold), self.slave_id)

        if self.stage_tick_treshold == 0.0:
            self.stage_tick_treshold = 1.0
        self.q.set_tick_timeout_treshold(3 * self.stage_tick_treshold * self.timeout_tick_factor)

        send_msg(KAFL_TAG_REQ_SAMPLING, bitmap, self.comm.to_master_from_slave_queue, source=self.slave_id)

    def __respond_bitmap_req(self, response):
        self.q.set_payload(response.data)
        while True:
            try:
                bitmap = self.q.send_payload()
                break
            except:
                log_slave("__respond_bitmap_req failed...\n%s"%(traceback.format_exc()), self.slave_id)
                self.__restart_vm()
        send_msg(KAFL_TAG_REQ_BITMAP, bitmap, self.comm.to_master_from_slave_queue, source=self.slave_id)

    def __respond_bitmap_hash_req(self, response):
        self.q.set_payload(response.data)
        while True:
            try:
                bitmap = self.q.send_payload()
                break
            except:
                log_slave("__respond_bitmap_hash_req failed...", self.slave_id)
                log_slave("%s"%traceback.format_exc(), self.slave_id)
                self.__restart_vm()
        send_msg(KAFL_TAG_REQ_BITMAP_HASH, mmh3.hash64(bitmap), self.comm.to_master_from_slave_queue, source=self.slave_id)


    def __respond_benchmark_req(self, response):
        payload = response.data[0]
        benchmark_rate = response.data[1]
        for i in range(benchmark_rate):
            self.q.set_payload(payload)
            self.q.send_payload()
            if self.q.crashed or self.q.timeout or self.q.kasan:
                self.__restart_vm()
        send_msg(KAFL_TAG_REQ_BENCHMARK, None, self.comm.to_master_from_slave_queue, source=self.slave_id)

    def __respond_redqueen_req(self, response):
        payload = response.data[0]
        self.q.set_payload(payload)
        if not self.q.execute_in_redqueen_mode(se_mode=False):
            self.__restart_vm()
            send_msg(KAFL_TAG_REQ_REDQUEEN, True, self.comm.to_master_from_slave_queue, source=self.slave_id)
            return
        send_msg(KAFL_TAG_REQ_REDQUEEN, True, self.comm.to_master_from_slave_queue, source=self.slave_id)


    def __perform_trim(self, size):
        original_bitmap = self.q.send_payload()
        new_size = size
        last_size = size

        for i in range(2,32):
            if last_size != (size-size/i) and (size-size/i) > 10:
                self.q.modify_payload_size(size-size/i)
                if original_bitmap == self.q.send_payload():
                    new_size = size-size/i
                    break
                else:
                    last_size = size-size/i
            else:
                break
        if size != new_size:
            log_slave("TRIM: " + "{0:.2f}".format(((new_size*1.0)/(size*1.0))*100.0) + "% (" + str(new_size) + "/" + str(size) + ")", self.slave_id)
            self.q.modify_payload_size(new_size)
            return new_size
        else:
            self.q.modify_payload_size(size)
            return size

    def error_handler(self):
        return self.q.crashed or self.q.timeout or self.q.kasan

    def __respond_verification(self, response):

        jobs = response.data[0]
        methods = response.data[1]

        results = []
        i = 0
        self.comm.slave_locks_A[self.slave_id].acquire()

        while True:
                payload, payload_shm_size = self.q.copy_master_payload(self.comm.get_master_payload_shm(self.slave_id), i, self.comm.get_master_payload_shm_size())

                payload_content_len_init = struct.unpack("I", payload[0:4])[0]

                payload_content_len = perform_trim(payload_content_len_init, self.q.send_payload, self.q.modify_payload_size, self.error_handler)

                if payload_content_len_init != payload_content_len:
                    log_slave("TRIM: " + "{0:.2f}".format(((payload_content_len*1.0)/(payload_content_len_init*1.0))*100.0) + "% (" + str(payload_content_len) + "/" + str(payload_content_len_init) + ")", self.slave_id)

                patches = jobs[0]
                if len(patches) > 0:
                    log_slave("Got payload to fix with size: %d and patches %s"%( payload_content_len, patches), self.slave_id )

                    if len(patches):
                        log_redq("Slave "+str(self.slave_id)+" Orig  Payload: " + repr(payload[4:4+payload_content_len]))
                        hash = HashFixer(self.q, self.redqueen_state)
                        new_payload = hash.try_fix_data(payload[4:4+payload_content_len])

                        if new_payload:
                            log_redq("Slave "+str(self.slave_id)+"Fixed Payload: " + repr("".join(map(chr,new_payload))))
                            payload = payload[:4]+"".join(map(chr,new_payload))
                            self.q.set_payload(new_payload)

                start_time = time.time()
                bitmap = self.q.send_payload(apply_patches=False)
                performance = time.time() - start_time
                log_slave("performance: " + str(1.0/performance) + " -> " + str(performance), self.slave_id)
                break
                    

        if not bitmap:
            log_slave("SHM ERROR....", self.slave_id)

        new_bits = self.q.copy_bitmap(self.comm.get_bitmap_shm(self.slave_id), i, self.comm.get_bitmap_shm_size(),
                                      bitmap, payload, payload_shm_size, effector_mode_hash=None, apply_patches = False)
        if new_bits:
            self.q.copy_mapserver_payload(self.comm.get_mapserver_payload_shm(self.slave_id), i, self.comm.get_mapserver_payload_shm_size())
        
        results.append(FuzzingResult(i, self.q.crashed, self.q.timeout, self.q.kasan, jobs[i], self.slave_id, performance, methods[i], mmh3.hash64(bitmap), reloaded=(self.q.timeout or self.q.crashed or self.q.kasan), new_bits=new_bits, qid=self.slave_id))

        self.comm.slave_locks_B[self.slave_id].release()
        send_msg(KAFL_TAG_RESULT, results, self.comm.to_mapserver_queue, source=self.slave_id)

    def interprocess_proto_handler(self):
        response = recv_msg(self.comm.to_slave_queues[self.slave_id])

        if response.tag == KAFL_TAG_JOB:
            self.__respond_job_req(response)
            send_msg(KAFL_TAG_REQ, self.q.qemu_id, self.comm.to_master_queue, source=self.slave_id)

        elif response.tag == KAFL_TAG_REQ_PING:
            send_msg(KAFL_TAG_REQ_PING, self.q.qemu_id, self.comm.to_master_queue, source=self.slave_id)

        elif response.tag == KAFL_TAG_UPDATE_REDQUEEN:
            self.redqueen_state.update_redqueen_patches(self.q.redqueen_workdir)
            self.q.send_payload(apply_patches=False)
            self.q.send_payload(apply_patches=True)
            send_msg(KAFL_TAG_UPDATE_REDQUEEN, self.q.qemu_id, self.comm.to_master_queue, source=self.slave_id)

        elif response.tag == KAFL_TAG_REQ_BITMAP:
            self.__respond_bitmap_req(response)

        elif response.tag == KAFL_TAG_REQ_BITMAP_HASH:
            self.__respond_bitmap_hash_req(response)

        elif response.tag == KAFL_TAG_REQ_SAMPLING:
            self.__respond_sampling_req(response)

        elif response.tag == KAFL_TAG_REQ_BENCHMARK:
            self.__respond_benchmark_req(response)  

        elif response.tag == KAFL_TAG_REQ_REDQUEEN:
            self.__respond_redqueen_req(response)   

        elif response.tag == KAFL_TAG_REQ_VERIFY:
            self.__respond_verification(response)
            send_msg(KAFL_TAG_REQ, self.q.qemu_id, self.comm.to_master_queue, source=self.slave_id)

        else:
            log_slave("Received TAG: " + str(response.tag), self.slave_id)

    def loop(self):
        self.comm.reload_semaphore.acquire()
        self.q.start()
        self.comm.reload_semaphore.release()
            
        send_msg(KAFL_TAG_START, self.q.qemu_id, self.comm.to_master_queue, source=self.slave_id)
        send_msg(KAFL_TAG_REQ, self.q.qemu_id, self.comm.to_master_queue, source=self.slave_id)
        while True:
            if self.comm.slave_termination.value:
                return
            self.interprocess_proto_handler()