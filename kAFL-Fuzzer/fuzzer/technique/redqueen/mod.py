"""
This file is part of the Redqueen fuzzer.

Cornelius Aschermann, 2019 <cornelius.aschermann@rub.de> 
Sergej Schumilo, 2019 <sergej@schumilo.de> 

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

from common.debug import logger
import ipdb
import os.path
import socket
import sys
import json
import struct
import re
from array import array
import parser
import itertools
from hash_patch import HashPatcher
from fuzzer.state import RedqueenState
from shutil import copyfile
from common.debug import log_redq

MAX_NUMBER_PERMUTATIONS = 1000 # number of trials per address, lhs and encoding

se_saved_counter = 0

class RedqueenInfoGatherer:
    def __init__(self):
        self.num_alternative_inputs = 0
        self.se_path = None
        self.workdir = None
        self.num_mutations = 0
        self.verbose = False

    def make_paths(self, workdir):
        global se_saved_counter
        se_saved_counter += 1
        self.se_path = workdir.base_path+"/se_%d"%(se_saved_counter)
        self.workdir = workdir
        os.mkdir(self.se_path)

    def get_info(self, input_data):
        self.num_alternative_inputs += 1
        self.save_rq_data(self.num_alternative_inputs, input_data)
        with open(self.se_path+"/input_%d.bin"%(self.num_alternative_inputs),"wb") as f:
            f.write(input_data)

    def save_rq_data(self, id, data):
        if os.path.exists(self.workdir.redqueen()):
            copyfile(self.workdir.redqueen(), "%s/redqueen_result_%d.txt"%(self.se_path,id))
        if os.path.exists(self.workdir.symbolic()):
            copyfile(self.workdir.symbolic(), "%s/symbolic_result_%d.txt"%(self.se_path,id))
        if os.path.exists(self.workdir.pt_trace()):
            copyfile(self.workdir.pt_trace(),"%s/trace_result_%d.txt"%(self.se_path,id))
        if os.path.exists(self.workdir.code_dump()):
            copyfile(self.workdir.code_dump(),"%s/redqueen_vm.img"%(self.se_path))
        with open("%s/fin_%d.txt"%(self.se_path,id),"w") as f:
            f.write("OK")


    def get_symbolic_proposals(self):
        proposals = set()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        kafl_sock = '/tmp/rq_se_sock'
        try:
            sock.connect(kafl_sock)
            sock.sendall(self.se_path+"\n")
            buffer = ""
            while True:
                res = sock.recv(16)
                buffer += res
                if "\n" in res:
                    break
        except socket.error, msg:
            log_redq("SE failed to get SE response, maybe no demon running?")
            log_redq("SE %s"%msg)
            return []
        results = json.loads(buffer)
        log_redq("SE JSON:"+str(results))
        orig_id= self.num_alternative_inputs
        return parser.parse_se(self.se_path, results, orig_id)

    def __get_redqueen_proposals(self):
        num_colored_versions = self.num_alternative_inputs
        orig_id= self.num_alternative_inputs
        rq_info, ( num_mutations, offset_to_lhs_to_rhs_to_info ) =  parser.parse_rq(self.se_path, num_colored_versions, orig_id)
        self.rq_info = rq_info
        self.rq_offsets_to_lhs_to_rhs_to_info = offset_to_lhs_to_rhs_to_info
        self.num_mutations += num_mutations

    def get_hash_candidates(self):
        return self.rq_info.get_hash_candidates()

    def get_boring_cmps(self):
        return self.rq_info.boring_cmps

    def __get_se_proposals(self):
        self.se_offsets_to_lhs_to_rhs_to_info = {}

    def get_proposals(self):
        self.__get_redqueen_proposals()
        self.__get_se_proposals()

    def __enumerate_mutations(self, offsets_to_lhs_to_rhs_to_info):
        for offsets in offsets_to_lhs_to_rhs_to_info:
            for lhs in offsets_to_lhs_to_rhs_to_info[offsets]:
                for rhs in offsets_to_lhs_to_rhs_to_info[offsets][lhs]:
                    yield(offsets, lhs, rhs, offsets_to_lhs_to_rhs_to_info[offsets][lhs][rhs])

    def enumerate_mutations(self):
        for val in self.__enumerate_mutations(self.rq_offsets_to_lhs_to_rhs_to_info):
            yield val
        for val in self.__enumerate_mutations(self.se_offsets_to_lhs_to_rhs_to_info):
            yield val

    def run_mutate_redqueen(self, payload_array, func, kafl_state, skip_null=True):
	if kafl_state:
		kafl_state.technique = "REDQUEEN"
        for (offset, lhs, rhs, info) in self.enumerate_mutations():
            if self.verbose:
                log_redq("%s"%repr((offset, lhs, rhs, info)))
            RedqueenInfoGatherer.fuzz_data(payload_array, lambda data: func(data,[repr(lhs),repr(rhs)]+list(info.infos),offset), offset, lhs, rhs)


    def get_num_mutations(self):
        return self.num_mutations
    
    @staticmethod
    def replace_data(data, offset, repl):
        for o in range(len(repl)):
            data[offset+o] = repl[o]

    @staticmethod
    def fuzz_data_same_len(data, func, offset_tuple, repl_tuple):
        backup = {}
        #copy = data[:]
        for i,repl in zip(offset_tuple, repl_tuple):
            for j in xrange(i,i+len(repl)):
                #if j in backup:
                #    log_redq("ERROR OVERLAPPING TUPLES %s"%repr((offset_tuple, repl_tuple)) )
                backup[j] = data[j]

        for i,repl in zip(offset_tuple, repl_tuple):
            #log_redq("apply: %s"%repr(repl))
            #log_redq("before data: %s"%repr("".join(map(chr, data))))
            RedqueenInfoGatherer.replace_data(data, i, array('B',repl))
            #log_redq("after data: %s"%repr("".join(map(chr, data))))
        #log_redq("run data: %s"%repr("".join(map(chr, data))))
        func(data.tostring())
        for i in backup:
            data[i] = backup[i]
            #RedqueenInfoGatherer.replace_data(data, i, backup[i])
        #assert(len(copy)==len(data))
        #if copy != data:
        #    log_redq("orig: %s"%repr(copy))
        #   log_redq("now: %s"%repr(data))
        #    log_redq("backup %s"%repr(backup))
        #    for i in range(len(data)):
        #        if data[i] != copy[i]:
        #            log_redq("diff at %d (%d/%d)"%(i,copy[i], data[i]))
        #    assert(False)
    
    @staticmethod
    def fuzz_data_different_len(data, func, offset_tuple, pat_length_tuple, repl_tuple):
        res_str = ""
        last_offset = 0
        for i,orig_length, repl in zip(sorted(offset_tuple), pat_length_tuple, repl_tuple):
            res_str += data[last_offset:i].tostring()
            res_str += repl
            last_offset = i+orig_length
        res_str += data[last_offset:].tostring()
        func(res_str)
    
    @staticmethod
    def fuzz_data(data, func, offset_tuple, pat_tuple, repl_tuple):
        pat_len_tuple = map(len, pat_tuple)
        if  pat_len_tuple != map(len, repl_tuple):
            RedqueenInfoGatherer.fuzz_data_different_len(data, func, offset_tuple, pat_len_tuple, repl_tuple)
        else:
            RedqueenInfoGatherer.fuzz_data_same_len(data, func, offset_tuple, repl_tuple)
