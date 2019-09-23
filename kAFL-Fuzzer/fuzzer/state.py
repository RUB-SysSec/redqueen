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
import base64
from collections import deque
from multiprocessing import Process, Manager, Lock
from common.util import Singleton
from common.debug import log_redq
import os 

class RedqueenState:
    __metaclass__ = Singleton

    def __init__(self):
        manager = Manager()
        self.lock = Lock()
        self.blacklisted_hashes = manager.dict()
        self.candidate_hashes = manager.dict()
        self.blacklisted_compares = manager.dict()
        self.candidate_file_offsets = manager.dict()

    def get_candidate_file_offsets(self, addr):
        if addr in self.candidate_file_offsets:
            return self.candidate_file_offsets[addr]

    def add_candidate_file_offset(self, addr, file_offset):
        self.lock.acquire()
        assert(addr in self.candidate_file_offsets)
        map = self.candidate_file_offsets[addr]
        map[file_offset] = map.get(file_offset,0)+1
        self.candidate_file_offsets[addr] = map
        self.lock.release()

    def add_candidate_hash_addr(self, addr):
        self.lock.acquire()
        if not addr in self.blacklisted_hashes:
            if not addr in self.candidate_hashes:
                log_redq("Hash candidate: %x"%addr)
                self.candidate_hashes[addr]=1
                self.candidate_file_offsets[addr] = {}
        self.lock.release()

    def get_candidate_hash_addrs(self):
        return self.candidate_hashes.keys()

    def blacklist_hash_addr(self, addr):
        self.lock.acquire()
        if not addr in self.blacklisted_hashes:
            log_redq("Blacklist Hash: %x"%addr)
            self.blacklisted_hashes[addr]=1
            if addr in self.candidate_hashes:
                del self.candidate_hashes[addr]
        self.lock.release()

    def get_blacklisted_hash_addrs(self):
        return self.blacklisted_hashes.keys()

    def blacklist_cmp_addr(self, addr):
        self.blacklisted_compares[addr] = 1

    def update_redqueen_patches(self, workdir):
        with open(workdir.patches(),"w") as f:
            for addr in self.get_candidate_hash_addrs():
                hexaddr = hex(addr).rstrip("L").lstrip("0x")
                if hexaddr:
                    f.write(hexaddr+"\n")
            f.flush()
            os.fsync(f.fileno())

    def update_redqueen_whitelist(self, workdir, whitelist):
        with open(workdir.whitelist(),"w") as f:
            for addr in whitelist:
                hexaddr = hex(addr).rstrip("L").lstrip("0x")
                if hexaddr:
                    f.write(hexaddr+"\n")
            f.flush()
            os.fsync(f.fileno())

    def update_redqueen_blacklist(self, workdir):
        log_redq("update blacklist with: %s"%repr(self.blacklisted_compares.keys()))
        with open(workdir.blacklist(),"w") as f:
            for addr in self.blacklisted_compares.keys():
                hexaddr = hex(addr).rstrip("L").lstrip("0x")
                if hexaddr:
                    f.write(hexaddr+"\n")
            f.flush()
            os.fsync(f.fileno())

class GlobalState:
    __metaclass__ = Singleton

    def __init__(self, performance_rb_limit=5, max_performance_rb_limit=100):
        manager = Manager()
        self.values = manager.dict()
        self.performance_rb_list = manager.list()
        self.max_performance_rb_list = manager.list()

        self.performance_rb_limit = performance_rb_limit
        self.max_performance_rb_limit = max_performance_rb_limit


        """ tree.py values """
        self.values['level'] = 1
        self.values['max_level'] = 1

        self.values['ratio_coverage'] = 0.0
        self.values['ratio_bits'] = 0.0

        self.values['path_pending'] = 0
        self.values['path_unfinished'] = 0
        self.values['fav_pending'] = 0
        self.values['fav_unfinished'] = 0

        self.values['crash'] = 0
        self.values['crash_unique'] = 0
        self.values['kasan'] = 0
        self.values['kasan_unique'] = 0
        self.values['timeout'] = 0
        self.values['timeout_unique'] = 0



        """ master.py values """
        self.values['progress_redqueen'] = 0
        self.values['progress_bitflip'] = 0
        self.values['progress_arithmetic'] = 0
        self.values['progress_interesting'] = 0
        self.values['progress_havoc'] = 0
        self.values['progress_specific'] = 0

        self.values['progress_requeen_amount'] = 0
        self.values['progress_bitflip_amount'] = 0
        self.values['progress_arithmetic_amount'] = 0
        self.values['progress_interesting_amount'] = 0
        self.values['progress_havoc_amount'] = 0
        self.values['progress_specific_amount'] = 0

        self.values['interface_str'] = ""
        self.values['target_str'] = ""
        self.values['technique'] = ""
        self.values['total'] = 0

        self.values['cycles'] = 0
        self.values['hashes'] = 0
        self.values['favorites'] = 0
        self.values['pending'] = 0
        self.values['payload_size'] = 0

        init_time = time.time()
        self.values['inittime'] = init_time
        self.values['runtime'] = init_time
        self.values['last_hash_time'] = init_time

        self.values['performance_rb_position'] = 0
        self.values['max_performance_rb_position'] = 0

        self.values['preliminary'] = 0
        self.values['imports'] = 0


        self.values["time_redqueen"] = 0
        """ misc """
        self.values["payload"] = ""
        self.values["loading"] = True
        self.values["reload"] = False
        self.values["slaves_ready"] = 0

    def update_performance(self, value):
        """ performance ring buffer """
        if len(self.performance_rb_list) < self.performance_rb_limit:
            self.performance_rb_list.append(value)
        else:
            if self.values['performance_rb_position'] == self.performance_rb_limit:
                self.values['performance_rb_position'] = 0
            self.performance_rb_list[self.values['performance_rb_position']] = value
        self.values['performance_rb_position'] += 1

        """ max performance ring buffer """
        if len(self.max_performance_rb_list) < self.max_performance_rb_limit:
            self.max_performance_rb_list.append(value)
        else:
            if self.values['max_performance_rb_position'] == self.max_performance_rb_limit:
                self.values['max_performance_rb_position'] = 0
            self.max_performance_rb_list[self.values['max_performance_rb_position']] = value
        self.values['max_performance_rb_position'] += 1

    def get_performance(self):
        try:
            if len(self.performance_rb_list) == 0:
                return 0
            else:
                return (sum(self.performance_rb_list)/len(self.performance_rb_list))
        except:
            return 0

    def get_max_performance(self):
        try:
            if len(self.max_performance_rb_list) == 0:
                return 0
            else:
                return (sum(self.max_performance_rb_list)/len(self.max_performance_rb_list))
        except:
            return 0

    def __getitem__(self, key):
        return self.values[key]

    def __setitem__(self, key, item): 
        self.values[key] = item

    def save_data(self):
        pass

    def load_data(self, data):
        pass
