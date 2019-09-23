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

import json
import base64

from fuzzer.communicator import *
from fuzzer.protocol import *
from fuzzer.state import *
from common.util import read_binary_file
from fuzzer.technique.arithmetic import *
from fuzzer.technique.bitflip import *
import fuzzer.technique.havoc as havoc
from fuzzer.technique.interesting_values import *
from fuzzer.technique.debug import *
from fuzzer.technique.radamsa import *
from fuzzer.technique.redqueen.mod import *
from fuzzer.technique.redqueen.colorize import ColorizerStrategy
from fuzzer.technique.redqueen.workdir import RedqueenWorkdir
from fuzzer.tree import KaflNodeType
from common.util import get_seed_files, check_state_exists, json_dumper
from common.config import FuzzerConfiguration
from common.debug import log_master, log_redq
from shutil import copyfile
import collections
import mmh3
import traceback
from fuzzer.fuzz_methods import fuzz_methode, METHODE_UNKOWN, METHODE_REDQUEEN, METHODE_SE, \
                                METHODE_BITFLIP_8, METHODE_BITFLIP_16, METHODE_BITFLIP_32, METHODE_ARITHMETIC_8, \
                                METHODE_ARITHMETIC_16, METHODE_ARITHMETIC_32, METHODE_INTERESTING_8, METHODE_INTERESTING_16, \
                                METHODE_INTERESTING_32, METHODE_HAVOC, METHODE_SPLICING, METHODE_RADAMSA, METHODE_IMPORT, METHODE_DICT_BF

from fuzzer.technique.redqueen.cmp import enable_hammering

import os, mmap
__author__ = 'Sergej Schumilo'

COLORIZATION_TIMEOUT = 5
COLORIZATION_COUNT = 1 #only n colorized versions of the input
COLORIZATION_STEPS = 1500

class MasterProcess:

    HAVOC_MULTIPLIER = 0.5
    RADAMSA_DIV = 10

    def __init__(self, comm):
        self.comm = comm
        self.kafl_state = GlobalState()
        self.redqueen_state = RedqueenState()
        self.payload = ""

        self.counter = 0
        self.round_counter = 0
        self.start = time.time()
        self.benchmark_time = time.time()
        self.counter_offset = 0
        self.payload_buffer = []
        self.methode_buffer = []
        self.byte_map = []
        self.stage_abortion = False
        self.abortion_counter = 0

        self.mapserver_status_pending = False

        self.config = FuzzerConfiguration()
        self.skip_zero = self.config.argument_values['s']
        self.refresh_rate = self.config.config_values['UI_REFRESH_RATE']
        self.use_effector_map = self.config.argument_values['d']
        self.arith_max = FuzzerConfiguration().config_values["ARITHMETIC_MAX"]


        self.seen_addr_to_value = {}

        self.mode_se_only = False
        self.mode_fix_checksum = self.config.argument_values["fix_hashes"]

        if not self.config.argument_values['D']:
            self.use_effector_map = False


        self.havoc_on_demand = False 

        if FuzzerConfiguration().argument_values['hammer_jmp_tables']:
            enable_hammering()

        log_master("havoc_on_demand: " + str(self.havoc_on_demand))
        log_master("Use effector maps: " + str(self.use_effector_map))

    def __start_processes(self):
        for i in range(self.comm.num_processes):
            start_time = time.time()
            recv_tagged_msg(self.comm.to_master_queue, KAFL_TAG_START)
            self.kafl_state["slaves_ready"] += 1

        self.kafl_state["loading"] = False
        self.kafl_state["inittime"] = time.time()
        if not self.config.load_old_state:
            self.kafl_state["runtime"] = time.time()

    def __redqueen_handler(self, payload, addr, offset, affected_bytes=None):
        self.kafl_state["progress_redqueen"] += 1
        self.kafl_state["total"] += 1
        self.__buffered_handler(payload, affected_bytes=affected_bytes, methode=fuzz_methode(methode_type=METHODE_REDQUEEN, redqueen_cmp = addr, input_byte = offset))

    def __bitflip_handler(self, payload, no_data=False, affected_bytes=None):
        if not no_data:
            self.kafl_state["progress_bitflip"] += 1
            self.kafl_state["total"] += 1
            self.__buffered_handler(payload, affected_bytes=affected_bytes, methode=fuzz_methode(methode_type=METHODE_BITFLIP_8))

    def __arithmetic_handler(self, payload, no_data=False):
        if not no_data:
            self.kafl_state["progress_arithmetic"] += 1
            self.kafl_state["total"] += 1
            self.__buffered_handler(payload, methode=fuzz_methode(methode_type=METHODE_ARITHMETIC_32))

    def __interesting_handler(self, payload, no_data=False):
        if not no_data:
            self.kafl_state["progress_interesting"] += 1
            self.kafl_state["total"] += 1
            self.__buffered_handler(payload, methode=fuzz_methode(methode_type=METHODE_INTERESTING_32))

    def __havoc_handler(self, payload, no_data=False):
        if not no_data:
            self.kafl_state["progress_havoc"] += 1
            self.kafl_state["total"] += 1
            self.__buffered_handler(payload, methode=fuzz_methode(methode_type=METHODE_HAVOC))

    def __dict_bf_handler(self, payload, no_data=False):
        if not no_data:
            self.kafl_state["progress_havoc"] += 1
            self.kafl_state["total"] += 1
            self.__buffered_handler(payload, methode=fuzz_methode(methode_type=METHODE_DICT_BF))

    def __splicing_handler(self, payload, no_data=False):
        if not no_data:
            self.kafl_state["progress_havoc"] += 1
            self.kafl_state["total"] += 1
            self.__buffered_handler(payload, methode=fuzz_methode(methode_type=METHODE_SPLICING))

    def __radamsa_handler(self, payload, no_data=False):
        if not no_data:
            self.kafl_state["progress_specific"] += 1
            self.kafl_state["total"] += 1
            self.__buffered_handler(payload, methode=fuzz_methode(methode_type=METHODE_RADAMSA))

    def __buffered_handler(self, payload, affected_bytes=None, last_payload=False, methode=fuzz_methode(methode_type=METHODE_UNKOWN)):
        if not self.stage_abortion:
            if not last_payload:
                self.payload_buffer.append(payload[:(64<<10)])
                self.methode_buffer.append(methode)
                if affected_bytes:
                    self.byte_map.append(affected_bytes)
                if len(self.payload_buffer) == self.comm.tasks_per_requests:
                    self.__master_handler(self.methode_buffer)
                    self.payload_buffer = []
                    self.methode_buffer = []
                    self.byte_map = []
            else:
                if len(self.payload_buffer) != 0:
                    self.__master_handler(self.methode_buffer)
                    self.payload_buffer = []
                    self.byte_map = []
                    self.methode_buffer = []

    def __master_handler(self, methods):
        if (time.time() - self.start) >= self.refresh_rate: 
            end = time.time()

            self.kafl_state.update_performance(int(((self.counter * 1.0) / (end - self.start))))
            self.start = time.time()
            self.counter = 0

        while True:
            msg = recv_msg(self.comm.to_master_queue)
            if msg.tag == KAFL_TAG_REQ:
                self.__task_send(self.payload_buffer, [None]*len(self.payload_buffer), msg.data, self.comm.to_slave_queues[int(msg.data)], methods)
                self.abortion_counter += len(self.payload_buffer)
                self.counter += len(self.payload_buffer)
                self.round_counter += len(self.payload_buffer)
                break
            elif msg.tag == KAFL_TAG_ABORT_REQ:
                log_master("Abortion request received...")
                self.stage_abortion = True
                self.payload_buffer = []
                self.byte_map = []
                return
            else:
                raise Exception("Unknown msg-tag received in master process...")

    def __get_num_of_finds(self):
        if self.stage_abortion:
            send_msg(KAFL_TAG_UNTOUCHED_NODES, self.abortion_counter, self.comm.to_mapserver_queue)
        else:
            send_msg(KAFL_TAG_UNTOUCHED_NODES, self.round_counter, self.comm.to_mapserver_queue)
        result = recv_msg(self.comm.to_master_from_mapserver_queue).data
        log_master("Current findings: " + str(result))
        return result

    def __recv_next(self, finished, performance):
        if finished or self.stage_abortion:
            send_msg(KAFL_TAG_NXT_FIN, [self.round_counter, performance], self.comm.to_mapserver_queue)
        else:
            send_msg(KAFL_TAG_NXT_UNFIN, [self.round_counter, performance], self.comm.to_mapserver_queue)
        msg = recv_msg(self.comm.to_master_from_mapserver_queue)
        payload = msg.data
        if msg.tag == KAFL_TAG_NXT_FIN:
            return payload, False
        else:
            return payload, True

    def __task_send(self, tasks, data, qid, dest, methods, tag=KAFL_TAG_JOB):
        fs_shm = self.comm.get_master_payload_shm(int(qid))
        size = self.comm.get_master_payload_shm_size()
        for i in range(len(tasks)):
            fs_shm.seek(size * i)
            input_len = to_string_32(len(tasks[i]))
            fs_shm.write(input_len)
            fs_shm.write(tasks[i])
        if self.byte_map:
            data = self.byte_map
        assert(len(tasks)==len(data))
        send_msg(tag, [data, methods], dest)

    def __request_bitmap(self, payload):
        send_msg(KAFL_TAG_REQ_BITMAP, payload, self.comm.to_slave_queues[0])
        msg = recv_tagged_msg(self.comm.to_master_from_slave_queue, KAFL_TAG_REQ_BITMAP)
        return msg.data

    def __commission_effector_map(self, bitmap):
        log_master("__commission_effector_map")
        send_msg(KAFL_TAG_REQ_EFFECTOR, bitmap, self.comm.to_mapserver_queue)

    def __get_effector_map(self, bitflip_amount):
        log_master("__get_effector_map")
        send_msg(KAFL_TAG_GET_EFFECTOR, bitflip_amount, self.comm.to_mapserver_queue)
        msg = recv_msg(self.comm.to_master_from_mapserver_queue)
        return msg.data

    def __sync_redqueen(self, redqueen_amount):
        if not self.stage_abortion:
            send_msg(KAFL_TAG_REDQUEEN_SYNC, redqueen_amount, self.comm.to_mapserver_queue)
        else:
            send_msg(KAFL_TAG_REDQUEEN_SYNC, self.abortion_counter, self.comm.to_mapserver_queue)
        self.round_counter = 0
        self.counter = 0
        self.abortion_counter = 0
        while True:
            data = recv_msg(self.comm.to_master_from_mapserver_queue)
            if KAFL_TAG_REDQUEEN_SYNC == data.tag:
                return

    def __sync_verification(self, verification_amoun):
        send_msg(KAFL_TAG_REQ_VERIFY_SYNC, verification_amoun, self.comm.to_mapserver_queue)
        while True:
            data = recv_msg(self.comm.to_master_from_mapserver_queue)
            if KAFL_TAG_REQ_VERIFY_SYNC == data.tag:
                return
            else:
                log_master("__sync_verification error?!")

    def __benchmarking(self, payload):
        c = 0
        runs = 3
        log_master("Initial benchmark...")
        start_run = time.time()
        send_msg(KAFL_TAG_REQ_BENCHMARK, [payload, runs], self.comm.to_slave_queues[0])
        recv_tagged_msg(self.comm.to_master_from_slave_queue, KAFL_TAG_REQ_BENCHMARK)

        multiplier = int(5 / (time.time()-start_run))
        if multiplier == 0:
            multiplier = 1

        log_master("Initial benchmark multiplier: " + str(multiplier))

        self.__start_benchmark(0)
        for slave in self.comm.to_slave_queues:
            send_msg(KAFL_TAG_REQ_BENCHMARK, [payload, multiplier*runs], slave)
            c += 1
        for i in range(c):
            recv_tagged_msg(self.comm.to_master_from_slave_queue, KAFL_TAG_REQ_BENCHMARK)
            self.round_counter += multiplier*runs

        value = self.__stop_benchmark()
        self.round_counter = 0
        log_master("Initial benchmark result: " + str(value) + " t/s")
        for i in range(2):
            self.kafl_state.update_performance(value)

    def __redqueen(self, payload):
        send_msg(KAFL_TAG_REQ_REDQUEEN, [payload], self.comm.to_slave_queues[0])
        msg = recv_tagged_msg(self.comm.to_master_from_slave_queue, KAFL_TAG_REQ_REDQUEEN)
        return msg.data

    def __get_bitmap_hash(self, payload):
        send_msg(KAFL_TAG_REQ_BITMAP_HASH, payload, self.comm.to_slave_queues[0])
        msg = recv_tagged_msg(self.comm.to_master_from_slave_queue, KAFL_TAG_REQ_BITMAP_HASH)
        return msg.data

    def __sampling(self, payload, initial_run=False):
        c = 0
        max_slaves = multiprocessing.cpu_count()/2
        for slave in self.comm.to_slave_queues:
            if(initial_run):
                send_msg(KAFL_TAG_REQ_SAMPLING, [payload, int(self.kafl_state.get_performance()/self.comm.num_processes)*3], slave)
            else:
                send_msg(KAFL_TAG_REQ_SAMPLING, [payload, int(self.kafl_state.get_performance()/self.comm.num_processes)], slave)
            c += 1
            if c == max_slaves:
                break
        for i in range(c):
            msg = recv_tagged_msg(self.comm.to_master_from_slave_queue, KAFL_TAG_REQ_SAMPLING)
        return msg.data

    def __start_benchmark(self, counter_offset):
        self.benchmark_time = time.time()
        self.counter_offset = counter_offset

    def __stop_benchmark(self):
        end = time.time()
        return int((((self.round_counter-self.counter_offset) * 1.0) / (end - self.benchmark_time)))

    def __init_fuzzing_loop(self):
        self.kafl_state["cycles"] = 0
        self.__start_processes()

        if self.config.load_old_state:
            log_master("State exists!")
        else:
            log_master("State does not exist!")
            payloads = get_seed_files(self.config.argument_values['work_dir'] + "/corpus")
            data = []
            for payload in payloads:
                bitmap = self.__request_bitmap(payload)
                data.append((payload, bitmap))
            send_msg(KAFL_INIT_BITMAP, data, self.comm.to_mapserver_queue)
            self.payload = payloads[0]

    def __calc_stage_iterations(self):
        self.kafl_state["progress_redqueen"] = 0
        self.kafl_state["progress_bitflip"] = 0
        self.kafl_state["progress_arithmetic"] = 0
        self.kafl_state["progress_interesting"] = 0
        self.kafl_state["progress_havoc"] = 0
        self.kafl_state["progress_specific"] = 0
        self.kafl_state["payload_size"] = len(self.payload)
        self.kafl_state["payload"] = self.payload

        limiter_map = []
        for i in range(len(self.payload)):
            limiter_map.append(True)
        if self.config.argument_values['i']:
            for ignores in self.config.argument_values['i']:
                log_master("Ignore-range 0: " + str(ignores[0]) + " " + str(min(ignores[0], len(self.payload))))
                log_master("Ignore-range 1: " + str(ignores[1]) + " " + str(min(ignores[1], len(self.payload))))
                for i in range(min(ignores[0], len(self.payload)), min(ignores[1], len(self.payload))):
                    limiter_map[i] = False

        if self.config.argument_values['D']:
            self.kafl_state["progress_bitflip_amount"] = bitflip_range(self.payload, skip_null=self.skip_zero, effector_map=limiter_map)
            self.kafl_state["progress_arithmetic_amount"] = arithmetic_range(self.payload, skip_null=self.skip_zero,  effector_map=limiter_map, set_arith_max=self.arith_max)
            self.kafl_state["progress_interesting_amount"] = interesting_range(self.payload, skip_null=self.skip_zero,  effector_map=limiter_map)
        else:
            self.kafl_state["progress_bitflip_amount"] = 0
            self.kafl_state["progress_arithmetic_amount"] = 0
            self.kafl_state["progress_interesting_amount"] = 0

        self.kafl_state["progress_havoc_amount"] = havoc.havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER)
        self.kafl_state["progress_specific_amount"] = havoc.havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER)/self.RADAMSA_DIV

        self.__start_benchmark(self.round_counter)
        return limiter_map

    def __perform_bechmark(self):
        if self.config.argument_values['n']:
            self.kafl_state["technique"] = "BENCHMARKING"
            self.__benchmarking(self.payload)

    def __perform_sampling(self):
        if self.config.argument_values['n']:
            self.kafl_state["technique"] = "PRE-SAMPLING"
            if self.kafl_state["total"] == 0:
                self.__sampling(self.payload, initial_run=True)

    def __check_colorization(self, orig_hash, payload_array, min, max):
        backup = payload_array[min:max]
        for i in xrange(min,max):
            payload_array[i] = random.randint(0,255)
        send_msg(KAFL_TAG_OUTPUT, self.kafl_state, self.comm.to_update_queue)
        hash = self.__get_bitmap_hash(payload_array)
        if hash == orig_hash:
            return True
        else:
            payload_array[min:max]=backup
            return False

    def __colorize_payload(self, hash, payload_array):
        c = ColorizerStrategy(len(payload_array), lambda min,max: self.__check_colorization(hash, payload_array, min, max))
        t = time.time()
        i = 0
        while True:
            if i >= COLORIZATION_STEPS and time.time()-t > COLORIZATION_TIMEOUT: #TODO add to config
                break
            if i% 20 == 0:
                log_master("colorizing step %d,"%(i))
            if len(c.unknown_ranges) == 0:
                break;
            c.colorize_step()
            i += 1

    def __get_bitmap_hash_robust(self, payload_array):
        self.__get_bitmap_hash(payload_array)
        hashes = [self.__get_bitmap_hash(payload_array) for i in xrange(3)]
        if len(set(hashes)) == 1:
            return hashes[0]
        log_master("Hash Doesn't seem Stable")
        return None


    def __perform_coloring(self, payload_array):
        if self.config.argument_values['r']:
            self.kafl_state["technique"] = "COLORING"
            log_master("Initial Redqueen Colorize...")
            hash = self.__get_bitmap_hash_robust(payload_array)
            if hash == None:
                return None
            log_master("Orig Redqueen Colorize...(" + str(hash)+")")

            colored_arrays = []
            for i in xrange(COLORIZATION_COUNT):
                if len(colored_arrays) >= COLORIZATION_COUNT:
                    break
                arr = array("B", payload_array)
                self.__colorize_payload(hash, arr)
                new_hash = self.__get_bitmap_hash(arr)
                if(new_hash == hash):
                    colored_arrays.append(arr)
                    log_master("found good hash")
                else:
                    log_master("found bad hash: "+repr(new_hash)+" retry")
                    return None

            colored_arrays.append(payload_array)
            return colored_arrays

    def __remove_dup_proposals(self, proposals):
        res = {}
        for prop in proposals:
            res[prop.get_dedup_tuple()] = prop
        return res.values()

    def __perform_redqueen(self, payload_array, colored_alternatives):
        if self.config.argument_values['r']:
            t = time.time()
            rq_info = RedqueenInfoGatherer()
            rq_info.make_paths(RedqueenWorkdir(0))
            rq_info.verbose = False
            for payload in colored_alternatives:
                if self.__redqueen(payload):
                    self.__sync_redqueen(0)
                    self.kafl_state["technique"] = "REDQUEEN"
                    rq_info.get_info(payload)

            if not self.mode_se_only:
                rq_info.get_proposals()

                self.kafl_state["progress_requeen_amount"] = rq_info.get_num_mutations()
                log_master("Redqueen Stage...(" + str(self.kafl_state["progress_requeen_amount"]) + ")")
                rq_info.run_mutate_redqueen(payload_array, self.__redqueen_handler, kafl_state=self.kafl_state, skip_null=True)

                if self.mode_fix_checksum:
                    for addr in rq_info.get_hash_candidates():
                        self.redqueen_state.add_candidate_hash_addr(addr)

                self.__buffered_handler(None, last_payload=True)
                log_master("Redqueen Sync...")
                tmp_progress_redqueen = self.kafl_state["progress_redqueen"]
                self.kafl_state["progress_redqueen"] = self.kafl_state["progress_requeen_amount"]

                self.__sync_redqueen(tmp_progress_redqueen)
            self.__update_redqueen_slaves()

            duration = time.time()-t
            self.kafl_state["time_redqueen"] = self.kafl_state["time_redqueen"]+duration
            log_redq("TIME IN REDQUEEN: %fs"%self.kafl_state["time_redqueen"])

    def __perform_verification(self, input_count):

        self.kafl_state["technique"] = "VERIFICATION"

        log_master("Sync...(" + str(self.round_counter) + " inputs)")
        self.__sync_verification(self.round_counter)
        log_master("Verification...(" + str(input_count) + " inputs)")

        i = 0
        for path in glob.glob(self.config.argument_values['work_dir'] + "/preliminary/preliminary_*"):
            if (time.time() - self.start) >= self.refresh_rate:
                end = time.time()
                self.kafl_state.update_performance(int(((self.counter * 1.0) / (end - self.start))))
                self.start = time.time()
                self.counter = 0
            while True:
                msg = recv_msg(self.comm.to_master_queue)
                if msg.tag == KAFL_TAG_REQ:
                    payload = read_binary_file(path)

                    methode = fuzz_methode()
                    methode.read_from_file(self.config.argument_values['work_dir'], i+1, preliminary=True)
                    
                    self.__task_send([payload[:(64<<10)]],[self.redqueen_state.get_candidate_hash_addrs()], msg.data, self.comm.to_slave_queues[int(msg.data)], [methode], tag=KAFL_TAG_REQ_VERIFY)
                    i += 1
                    self.counter += 1
                    self.round_counter += 1
                    break
                else:
                    log_master("Unknown Tag (" + str(msg.tag) + ") received during verification...")

        log_master("Sync...(" + str(self.round_counter) + " inputs)")
        self.__sync_verification(self.round_counter)
        log_master("Verification done!")

    def __perform_import(self):

        import_count = len(glob.glob(self.config.argument_values['work_dir'] + "/imports/*"))

        if import_count == 0:
            return 

        self.kafl_state["technique"] = "IMPORT"

        log_master("Sync...(" + str(self.round_counter) + " inputs)")
        self.__sync_verification(self.round_counter)
        log_master("Importing...(" + str(import_count) + " inputs)")

        i = 0
        for path in glob.glob(self.config.argument_values['work_dir'] + "/imports/*"):
            if (time.time() - self.start) >= self.refresh_rate:
                end = time.time()
                self.kafl_state.update_performance(int(((self.counter * 1.0) / (end - self.start))))
                self.start = time.time()
                self.counter = 0
            while True:
                msg = recv_msg(self.comm.to_master_queue)
                if msg.tag == KAFL_TAG_REQ:
                    payload = read_binary_file(path)
                    
                    self.__task_send([payload[:(64<<10)]],[self.redqueen_state.get_candidate_hash_addrs()], msg.data, self.comm.to_slave_queues[int(msg.data)], [fuzz_methode(METHODE_IMPORT)], tag=KAFL_TAG_REQ_VERIFY)
                    os.remove(path)
                    i += 1
                    self.counter += 1
                    self.round_counter += 1
                    break
                else:
                    log_master("Unknown Tag (" + str(msg.tag) + ") received during verification...")

        log_master("Sync...(" + str(self.round_counter) + " inputs)")
        self.__sync_verification(self.round_counter)
        log_master("Import done!")


    def __perform_deterministic(self, payload_array, limiter_map):
        if self.config.argument_values['D']:

            log_master("Bit Flip...")
            
            mutate_seq_walking_bits_array(payload_array,          self.__bitflip_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=limiter_map)
            mutate_seq_two_walking_bits_array(payload_array,      self.__bitflip_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=limiter_map)
            mutate_seq_four_walking_bits_array(payload_array,     self.__bitflip_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=limiter_map)

            if self.use_effector_map and len(payload_array) > 128:
                self.comm.effector_mode.value = True
                log_master("Request effector map")
                bitmap = self.__request_bitmap(self.payload)
                bitmap_hash = mmh3.hash64(bitmap)
                self.comm.effector_mode_hash_a.value = bitmap_hash[0]
                self.comm.effector_mode_hash_b.value = bitmap_hash[1]

                self.__commission_effector_map(bitmap)


                mutate_seq_walking_byte_array(payload_array,          self.__bitflip_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=limiter_map)

            if self.comm.sampling_failed_notifier.value:
                self.stage_abortion = True
                self.comm.sampling_failed_notifier.value = False
                self.comm.sampling_failed_notifier.value = False

            if self.use_effector_map and len(payload_array) > 128:
                self.__buffered_handler(None, last_payload=True)
                effector_map = self.__get_effector_map(self.kafl_state["progress_bitflip"])

                effector_map[0] = True;
                effector_map[len(payload_array)-1] = True;
                self.comm.effector_mode.value = False



            log_master("progress_bitflip: " + str(self.kafl_state["progress_bitflip"]))
            log_master("progress_bitflip_amount: " + str(self.kafl_state["progress_bitflip_amount"]))
            self.kafl_state["progress_bitflip_amount"] = self.kafl_state["progress_bitflip"]

            log_master("Bit Flip done...")
            if self.use_effector_map and len(payload_array) > 128:
                log_master("Use Effector Map...")
                self.comm.effector_mode.value = False
                self.byte_map = []
                self.kafl_state["progress_arithmetic_amount"] = arithmetic_range(self.payload, skip_null=self.skip_zero, effector_map=effector_map)
                self.kafl_state["progress_interesting_amount"] = interesting_range(self.payload, skip_null=self.skip_zero, effector_map=effector_map)
                self.kafl_state["technique"] = "EFF-SYNC"
                log_master("Effectormap size is " + str(sum(x is True for x in effector_map)))
                log_master("Effector arihmetic size is " + str(arithmetic_range(self.payload, skip_null=self.skip_zero, effector_map=effector_map)))
                log_master("Effector intersting size is " + str(interesting_range(self.payload, skip_null=self.skip_zero, effector_map=effector_map)))
                new_effector_map = []
                for i in range(len(effector_map)):
                    if any(effector_map[i-(i%8):i-(i%8)+8]) and any(limiter_map[i-(i%8):i-(i%8)+8]):
                        new_effector_map.append(True)
                    else:
                        new_effector_map.append(False)
                effector_map = new_effector_map
            else:
                log_master("No effector map!")
                effector_map = limiter_map

                self.kafl_state["progress_arithmetic_amount"] = arithmetic_range(self.payload, skip_null=self.skip_zero, effector_map=effector_map)
                self.kafl_state["progress_interesting_amount"] = interesting_range(self.payload, skip_null=self.skip_zero, effector_map=effector_map)


            mutate_seq_two_walking_bytes_array(payload_array,     self.__bitflip_handler, kafl_state=self.kafl_state, effector_map=effector_map)
            mutate_seq_four_walking_bytes_array(payload_array,    self.__bitflip_handler, kafl_state=self.kafl_state, effector_map=effector_map)
            self.__buffered_handler(None, last_payload=True)


            log_master("Arithmetic...")
            mutate_seq_8_bit_arithmetic_array(payload_array,      self.__arithmetic_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=effector_map, set_arith_max=self.arith_max)
            mutate_seq_16_bit_arithmetic_array(payload_array,     self.__arithmetic_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=effector_map, set_arith_max=self.arith_max)
            mutate_seq_32_bit_arithmetic_array(payload_array,     self.__arithmetic_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=effector_map, set_arith_max=self.arith_max)
            self.__buffered_handler(None, last_payload=True)
            self.kafl_state["progress_arithmetic"] = self.kafl_state["progress_arithmetic_amount"]

            log_master("Interesting...")

            mutate_seq_8_bit_interesting_array(payload_array,     self.__interesting_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=effector_map)
            mutate_seq_16_bit_interesting_array(payload_array,    self.__interesting_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=effector_map, set_arith_max=self.arith_max)
            mutate_seq_32_bit_interesting_array(payload_array,    self.__interesting_handler, skip_null=self.skip_zero, kafl_state=self.kafl_state, effector_map=effector_map, set_arith_max=self.arith_max)
            self.__buffered_handler(None, last_payload=True)
            self.kafl_state["progress_interesting"] = self.kafl_state["progress_interesting_amount"]

            self.kafl_state["technique"] = "PRE-SYNC"

  
    def __perform_dict(self, payload_array, payload):
        self.kafl_state["technique"] = "DICT-BF"
        log_master("Dict on %s"%repr(payload_array.tostring()))
        dict = havoc.get_redqueen_dict()
        log_redq("using %s"%repr(dict))
        counter = 0
        if len(payload_array) < 256:
            for addr in dict:
                for repl in dict[addr]:
                    if addr in self.seen_addr_to_value and (len(self.seen_addr_to_value[addr]) > 32 or repl in self.seen_addr_to_value[addr]):
                        continue
                    if not addr in self.seen_addr_to_value:
                        self.seen_addr_to_value[addr] = set()
                    self.seen_addr_to_value[addr].add(repl)
                    for i in range(len(payload_array)):
                        counter += 1
                        mutated =havoc.apply_dict_to_data(payload_array, repl, i).tostring()
                        self.__dict_bf_handler(mutated)
        log_redq("have performed %d iters"%counter)
        self.__buffered_handler(None, last_payload=True)

    def __perform_havoc(self, payload_array, payload, use_splicing):
        log_master("Havoc...")
        self.kafl_state["progress_bitflip"] = self.kafl_state["progress_bitflip_amount"]
        self.kafl_state["progress_arithmetic"] = self.kafl_state["progress_arithmetic_amount"]
        self.kafl_state["progress_interesting"] = self.kafl_state["progress_interesting_amount"]
        self.kafl_state["progress_redqueen"] = self.kafl_state["progress_requeen_amount"]

        if payload and payload.node_type == KaflNodeType.favorite:
            self.kafl_state["progress_havoc_amount"] = havoc.havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER * 2.0)
            self.kafl_state["progress_specific_amount"] = havoc.havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER * 2.0)/self.RADAMSA_DIV
        else:
            self.kafl_state["progress_havoc_amount"] = havoc.havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER)
            self.kafl_state["progress_specific_amount"] = havoc.havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER)/self.RADAMSA_DIV

        if not use_splicing:
            self.kafl_state["technique"] = "HAVOC"
            havoc.mutate_seq_havoc_array(payload_array, self.__havoc_handler, self.kafl_state["progress_havoc_amount"])
        else:
            self.kafl_state["technique"] = "SPLICING"
            havoc.mutate_seq_splice_array(payload_array, self.__splicing_handler, self.kafl_state["progress_havoc_amount"], self.kafl_state)
        self.__buffered_handler(None, last_payload=True)

        mutate_seq_radamsa_array(payload_array, self.__radamsa_handler, self.kafl_state["progress_specific_amount"], kafl_state=self.kafl_state)
        self.__buffered_handler(None, last_payload=True)
        

    def __perform_post_sync(self, finished):
        self.kafl_state["technique"] = "POST-SYNC"
        payload, finished_state = self.__recv_next(finished, self.__stop_benchmark())
        log_master("finished_state -> " + str(finished_state))
        self.payload = payload.load_payload()
        self.round_counter = 0
        self.stage_abortion = False
        self.abortion_counter = 0
        return payload, finished_state

    def __sync_slaves(self):
        tmp_progress_redqueen = self.kafl_state["progress_redqueen"]
        for s in self.comm.to_slave_queues:
            send_msg(KAFL_TAG_REQ_PING, None, s)
        for _ in self.comm.to_slave_queues:
            recv_tagged_msg(self.comm.to_master_queue, KAFL_TAG_REQ_PING)

    def __update_redqueen_slaves(self):
        for s in self.comm.to_slave_queues:
            send_msg(KAFL_TAG_UPDATE_REDQUEEN, None, s)
        for _ in self.comm.to_slave_queues:
            recv_tagged_msg(self.comm.to_master_queue, KAFL_TAG_UPDATE_REDQUEEN)

    def __toggle_preliminary_mode(self, state):
        if not state:
            self.__sync_slaves()
        send_msg(KAFL_TAG_REQ_PRELIMINARY, state, self.comm.to_mapserver_queue)
        response = recv_msg(self.comm.to_master_from_mapserver_queue)
        return response.data


    def wipe(self):
        filter_bitmap_fd = os.open("/dev/shm/kafl_filter0", os.O_RDWR | os.O_SYNC | os.O_CREAT)
        os.ftruncate(filter_bitmap_fd, self.config.config_values['BITMAP_SHM_SIZE'])
        filter_bitmap = mmap.mmap(filter_bitmap_fd, self.config.config_values['BITMAP_SHM_SIZE'], mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        for i in range(self.config.config_values['BITMAP_SHM_SIZE']):
            filter_bitmap[i] = '\x00'
        filter_bitmap.close()
        os.close(filter_bitmap_fd)

        filter_bitmap_fd = os.open("/dev/shm/kafl_tfilter", os.O_RDWR | os.O_SYNC | os.O_CREAT)
        os.ftruncate(filter_bitmap_fd, 0x1000000)
        filter_bitmap = mmap.mmap(filter_bitmap_fd, 0x1000000, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        for i in range(0x1000000):
            filter_bitmap[i] = '\x00'
        filter_bitmap.close()
        os.close(filter_bitmap_fd)


    def loop(self):
        finished_state = False
        finished = False
        payload = None

        self.__init_fuzzing_loop()
        self.__perform_bechmark()

        while True:

            self.__toggle_preliminary_mode(True)


            payload_array = array('B', self.payload)
            limiter_map = self.__calc_stage_iterations()

            if not finished_state:
                self.__perform_sampling()

                if self.config.argument_values['r']:
                    colored_alternatives = self.__perform_coloring(array('B', payload_array))
                    if colored_alternatives:
                        havoc.clear_redqueen_dict()
                        payload_array = array('B', colored_alternatives[0])
                        self.__perform_redqueen(payload_array, colored_alternatives)
                    else:
                        log_master("input is not stable, skip redqueen")
                self.__perform_deterministic(payload_array, limiter_map)
                finished = False

            preliminary_results = self.__toggle_preliminary_mode(False)
            log_master("Number of preliminary findings: " + str(preliminary_results))
            self.__perform_verification(preliminary_results)
            self.__perform_import()


            if self.havoc_on_demand:
                apply_havoc = (self.kafl_state["fav_pending"] < 2)
            else:
                apply_havoc = True

            if apply_havoc:

                num_of_finds = self.__get_num_of_finds()

                if True:
                    use_splicing = False
                    self.__perform_dict(payload_array, payload)
                    for i in range(16):
                        self.__toggle_preliminary_mode(True)
                        self.__perform_havoc(payload_array, payload, use_splicing=use_splicing)
                        finished = True
                        preliminary_results = self.__toggle_preliminary_mode(False)
                        log_master("Number of preliminary findings: " + str(preliminary_results))
                        self.__perform_verification(preliminary_results)
                        self.__perform_import()
                        num_of_finds_tmp = self.__get_num_of_finds()
                        if num_of_finds == num_of_finds_tmp or self.stage_abortion:
                            if i == 0:
                                use_splicing = True
                            else:
                                break
                        else:
                            num_of_finds = num_of_finds_tmp
                            log_master("Repeat!")
                            self.kafl_state["progress_havoc"] = 0
                            self.kafl_state["progress_specific"] = 0
                            self.kafl_state["progress_havoc_amount"] = havoc.havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER * 4)
                            self.kafl_state["progress_specific_amount"] = havoc.havoc_range(self.kafl_state.get_performance() * self.HAVOC_MULTIPLIER * 4)/self.RADAMSA_DIV
                            self.kafl_state["technique"] = "HAVOC"

            payload, finished_state = self.__perform_post_sync(finished)

    def save_data(self):
        """
        Method to store an entire master state to JSON file...
        """
        dump = {}
        for key, value in self.__dict__.iteritems():
            if key == "kafl_state":
                dump[key] = value.save_data()

        with open(self.config.argument_values['work_dir'] + "/master.json", 'w') as outfile:
            json.dump(dump, outfile, default=json_dumper)

        # Save kAFL Filter
        copyfile("/dev/shm/kafl_filter0", self.config.argument_values['work_dir'] + "/kafl_filter0")

    def load_data(self):
        """
        Method to load an entire master state from JSON file...
        """
        with open(FuzzerConfiguration().argument_values['work_dir'] + "/master.json", 'r') as infile:
            dump = json.load(infile)
            for key, value in dump.iteritems():
                if key == "kafl_state":
                    self.kafl_state.load_data(value)
                else:
                    setattr(self, key, value)

        copyfile(self.config.argument_values['work_dir'] + "/kafl_filter0", "/dev/shm/kafl_filter0")

