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

import os.path
import re
import copy
#import ipdb
import itertools
import sys
import struct

from common.debug import log_redq
from encoding import Encoders
from cmp import Cmp

def read_file(path):
    with open(path, 'r') as content_file:
        return content_file.read()

class RedqueenRunInfo:
    def __init__(self, id, was_colored, hook_info, input_data):
        self.id = id
        self.hook_info = hook_info
        self.input_data = input_data
        self.pattern_to_offsets = {}
        self.was_colored = was_colored

    def get_union_of_offsets(self, patterns):
        res = set()
        for pat in patterns:
            res |= self.get_offsets(self, pattern)
        return res

    def are_all_present(self, patterns):
        for pat in patterns:
            if not self.get_offsets(pat):
                return false
        return true

    def get_offset_tuple(self, pattern_tuple):
        return tuple([self.get_offsets(pat) for pat in pattern_tuple])

    def get_offsets(self, pattern):
        if pattern in self.pattern_to_offsets:
            return set(self.pattern_to_offsets[pattern])
        self.pattern_to_offsets[pattern] = self.calc_offsets(pattern)
        return set(self.pattern_to_offsets[pattern])

    def calc_offsets(self, pattern):
        res = set()
        start = 0
        while True:
            start = self.input_data.find(pattern, start)
            if start == -1: return res
            res.add(start)
            start += 1 # use start += 1 to find overlapping matches
        return res

class RedqueenInfo:
    def __init__(self):
        self.addr_to_cmp = {}
        self.addr_to_inv_cmp = {}
        self.run_infos = set()
        self.boring_cmps = set()

    def load(self, id, was_colored, path):
        hook_info = read_file("%s/redqueen_result_%d.txt"%(path,id))
        bin_info = read_file("%s/input_%d.bin"%(path, id) )
        return self.load_data(id, was_colored, hook_info, bin_info)

    def load_data(self, id, was_colored, hook_info, bin_info):
        run_info = RedqueenRunInfo(id, was_colored, hook_info , bin_info )
        self.run_infos.add(run_info)
        self.parse_run_info(run_info)
        return run_info
    
    def parse_run_info(self, run_info):
        self.run_infos.add(run_info)
        for line in run_info.hook_info.splitlines():
            self.parse_line_and_update_compares(run_info, line)

    @staticmethod
    def parse_line(line):
        m = re.search(r'([a-fA-F0-9]+)\s+(CMP|SUB|STR|LEA)\s+(8|16|32|64|512)\s+([a-fA-F0-9]+)\s*-\s*([a-fA-F0-9]+)\s*(IMM)?', line)
        assert(m)
        addr = int(m.group(1),16)
        type = m.group(2)
        size = int(m.group(3))
        is_imm = not not m.group(6)
        lhs = m.group(4).decode('hex')
        rhs = m.group(5).decode('hex')
        return addr, type, size, is_imm, lhs, rhs

    def add_run_result(self, run_info, addr, type, size, is_imm, lhs, rhs, addr_to_cmp):
        addr_to_cmp[addr] = addr_to_cmp.get(addr, Cmp(addr, type, size, is_imm))
        cmp = addr_to_cmp[addr]
        assert(cmp.addr == addr)
        assert(cmp.type == type)
        assert(cmp.size == size)
        assert(cmp.is_imm == is_imm)
        assert( len(lhs) == size/8 )
        assert( len(rhs) == size/8 )
        cmp.add_result(run_info, lhs, rhs)

    def parse_line_and_update_compares(self, run_info, line):
        addr, type, size,is_imm, lhs, rhs = RedqueenInfo.parse_line(line)
        if lhs == rhs:
            return
        self.add_run_result(run_info, addr, type, size, is_imm, lhs, rhs, self.addr_to_cmp)
        if not is_imm:
            self.add_run_result(run_info, addr, type, size, is_imm, rhs, lhs, self.addr_to_inv_cmp)

    def get_all_mutations(self):
        orig_run_info = [r for r in self.run_infos if r.was_colored == False]
        assert(len(orig_run_info) == 1)
        self.boring_cmps = set()
        orig_run_info = orig_run_info[0]
        offsets_to_lhs_to_rhs_to_info = {}
        num_mut = 0
        for addr_to_cmp in [self.addr_to_cmp, self.addr_to_inv_cmp]:
            for addr in addr_to_cmp: 
                cmp = addr_to_cmp[addr]
                was_cmp_interessting = False
                if len(cmp.run_info_to_pairs) == len(self.run_infos):
                    for (offsets, lhs, rhs, encoding) in cmp.calc_mutations(orig_run_info, len(self.run_infos)):
                        offsets, lhs, rhs = self.strip_unchanged_bytes_from_mutation_values(offsets, lhs, rhs)
                        was_cmp_interessting = True
                        offsets_to_lhs_to_rhs_to_info[offsets] = offsets_to_lhs_to_rhs_to_info.get(offsets, {})
                        offsets_to_lhs_to_rhs_to_info[offsets][lhs] = offsets_to_lhs_to_rhs_to_info[offsets].get(lhs, {})
                        if not rhs in offsets_to_lhs_to_rhs_to_info[offsets][lhs]:
                            num_mut += 1
                        offsets_to_lhs_to_rhs_to_info[offsets][lhs][rhs] = offsets_to_lhs_to_rhs_to_info[offsets][lhs].get(rhs, MutInfo())
                        offsets_to_lhs_to_rhs_to_info[offsets][lhs][rhs].add_info(addr, encoding)
                if not was_cmp_interessting:
                    self.boring_cmps.add(cmp.addr)
        return num_mut, offsets_to_lhs_to_rhs_to_info

    def strip_unchanged_bytes_from_mutation(self, offset, lhs, rhs):
        assert(len(lhs) == len(rhs))
        i = 0
        ll = len(lhs)
        res_lhss,res_rhss,res_offsets = [], [], []
        while i < ll:
            j = i
            while j<ll and lhs[j] != rhs[j]:
                j+= 1
            if j != i:
                res_lhss.append(lhs[i:j])
                res_rhss.append(rhs[i:j])
                res_offsets.append(offset+i)
            i=j+1
        return res_offsets, res_lhss, res_rhss

    def strip_unchanged_bytes_from_mutation_values(self, offsets, lhss, rhss):
        assert(len(offsets) == len(lhss))
        assert(len(offsets) == len(rhss))
        res_offsets, res_lhss, res_rhss = [], [], []
        for i in range(len(offsets)):
            if len(lhss[i]) != len(rhss[i]):
                res_offsets.append(offsets[i])
                res_lhss.append(lhss[i])
                res_rhss.append(rhss[i])
            else:
                new_offsets,new_lhss,new_rhss = self.strip_unchanged_bytes_from_mutation(offsets[i], lhss[i], rhss[i])
                res_offsets += new_offsets
                res_lhss += new_lhss
                res_rhss += new_rhss
        #log_redq("strip: %s -> %s"%( repr((offsets,lhss,rhss)), repr((res_offsets,res_lhss, res_rhss)) ) )
        return tuple(res_offsets), tuple(res_lhss), tuple(res_rhss)

    def get_hash_candidates(self):
        res = set()
        for addr in self.addr_to_cmp:
            cmp = self.addr_to_cmp[addr]
            if not cmp in self.boring_cmps and cmp.could_be_hash():
                res.add(addr)
        return res

class MutInfo:
    def __init__(self):
        self.infos = set()

    def add_info(self, addr,encoding):
        self.infos.add((addr, encoding.name(),))

    def __repr__(self):
        return "MutInfo<%s>"%(repr(self.infos))


def parse_se(path, se_data, orig_id):
        proposals = []
        bin_info = read_file("%s/input_%d.bin"%(path, orig_id) )
        run_info = RedqueenRunInfo(orig_id, False, None , bin_info )
        for repl in se_data:
            if len(repl["map"]) > 0:
                patterns = []
                offsets = []
                replacements = []
                for (lhs,rhs) in repl["map"]:
                    pat = lhs.decode("hex")
                    patterns.append(pat)
                    offsets.append(run_info.get_offsets(pat))
                    replacements.append( rhs.decode("hex"))
                proposals.append( SEMutation(patterns, offsets, replacements))
        return proposals

def parse_rq(path, num_files, orig_file_id):
    rq_info = RedqueenInfo()
    run_infos = [ rq_info.load(id, id != orig_file_id, path) for id in range(1,num_files+1) ]
    return rq_info,rq_info.get_all_mutations()

def parse_rq_data(hook_data, input_data):
    rq_info = RedqueenInfo()
    run_info = rq_info.load_data(1, False, hook_data, input_data)
    return rq_info.get_all_mutations()
