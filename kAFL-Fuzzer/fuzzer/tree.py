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
import random
import time
import os
import mmap
import lz4
import traceback
import sys
import mmh3

from common.config import FuzzerConfiguration
from common.debug import log_tree
from common.util import read_binary_file, atomic_write, json_dumper
from fuzzer.technique.helper import RAND
from common.qemu import QemuLookupSet

from fuzzer.fuzz_methods import fuzz_yield

from fuzzer.state import GlobalState

from ctypes import *
import inspect

class KaflNodeType:
    regular, favorite, crash, kasan, timeout, preliminary = range(6)

    def __init__(self):
        pass


class KaflNodeState:
    untouched, in_progress, finished = range(3)

    def __init__(self):
        pass

KaflNodeID = 1
KaflCrashID = 1
KaflKASanID = 1
KaflTimeoutID = 1
KaflPreliminaryID = 1

class KaflNode:
    def __init__(self, level, payload, bitmap, methode, sequence=None,
                 node_state=None, node_type=None, current=False, write_data=True, performance=None, new_byte_count=0, new_bit_count=0):
        global KaflNodeID, KaflCrashID, KaflKASanID, KaflTimeoutID, KaflPreliminaryID

        if methode:
            self.bb_delta = methode.bb_delta
        else:
            self.bb_delta = 0
        self.new_byte_count = new_byte_count
        self.new_bit_count = new_bit_count
        self.level = level
        self.current = current
        self.performance = performance

        self.fav_bits = 0

        if node_state:
            self.node_state = node_state
        else:
            self.node_state = KaflNodeState.untouched
        if node_type:
            self.node_type = node_type
        else:
            self.node_type = KaflNodeType.regular

        if self.node_type == KaflNodeType.regular or self.node_type == KaflNodeType.favorite:
            self.node_id = KaflNodeID
            KaflNodeID += 1
        elif self.node_type == KaflNodeType.crash:
            self.node_id = KaflCrashID
            KaflCrashID += 1
        elif self.node_type == KaflNodeType.kasan:
            self.node_id = KaflKASanID
            KaflKASanID += 1
        elif self.node_type == KaflNodeType.timeout:
            self.node_id = KaflTimeoutID
            KaflTimeoutID += 1
        elif self.node_type == KaflNodeType.preliminary:
            self.node_id = KaflPreliminaryID
            KaflPreliminaryID += 1
            
        if methode:
            if self.node_type == KaflNodeType.preliminary:
                methode.save_to_file(FuzzerConfiguration().argument_values['work_dir'], self.node_id, preliminary=True)
            elif self.node_type == KaflNodeType.regular or self.node_type == KaflNodeType.favorite:
                methode.save_to_file(FuzzerConfiguration().argument_values['work_dir'], self.node_id, preliminary=False)
            else:
                pass

        self.payload_hash = mmh3.hash(payload)

        self.bits = {}
        if write_data:
            self.__save_payload(payload)
            self.__write_eval_results()
            self.__process_bitmap(bitmap)
            if sequence:
                self.__save_payload_sequence(sequence)

        FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
        self.identifier = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in payload])
        if len(self.identifier) > 10:
            self.identifier = self.identifier[:10] + " (...)"
        self.payload_len = len(payload)


        if performance is None:
            self.performance = 0.0
            self.fav_factor = 10000000
        else:
            self.fav_factor = self.performance * self.payload_len


    def remove(self):
        global KaflNodeID, KaflCrashID, KaflKASanID, KaflTimeoutID, KaflPreliminaryID

        os.remove(self.__get_filename())
        if self.node_type == KaflNodeType.regular or self.node_type == KaflNodeType.favorite:
            KaflNodeID -= 1
        elif self.node_type == KaflNodeType.crash:
            KaflCrashID -= 1
        elif self.node_type == KaflNodeType.kasan:
            KaflKASanID -= 1
        elif self.node_type == KaflNodeType.timeout:
            KaflTimeoutID -= 1
        elif self.node_type == KaflNodeType.preliminary:
            KaflPreliminaryID -= 1

    def __process_bitmap(self, bitmap):
        j = 0
        for bit in bitmap:
            if bit != '\xff':
                self.bits[j] = ord(bit)
            j += 1
        self.bit_count = len(self.bits)

    def __get_filename(self):
        filename = ""

        if self.node_type == KaflNodeType.regular or self.node_type == KaflNodeType.favorite:
            filename = FuzzerConfiguration().argument_values['work_dir'] + "/corpus/payload_%05d"%self.node_id
        elif self.node_type == KaflNodeType.crash:
            filename = FuzzerConfiguration().argument_values['work_dir'] + "/findings/crash/crash_%05d"%self.node_id
        elif self.node_type == KaflNodeType.kasan:
            filename = FuzzerConfiguration().argument_values['work_dir'] + "/findings/kasan/kasan_%05d"%self.node_id
        elif self.node_type == KaflNodeType.timeout:
            filename = FuzzerConfiguration().argument_values['work_dir'] + "/findings/timeout/timeout_%05d"%self.node_id
        elif self.node_type == KaflNodeType.preliminary:
            filename = FuzzerConfiguration().argument_values['work_dir'] + "/preliminary/preliminary_%05d"%self.node_id
        return filename

    def __write_eval_results(self):
        with open(FuzzerConfiguration().argument_values['work_dir']+"/evaluation/findings.csv",'ab') as f:
            f.write("%s\n"%json.dumps([time.time()-GlobalState().values["inittime"], self.__get_filename()] ))

    def __save_payload(self, payload):
        atomic_write(self.__get_filename(), payload)

    def __save_payload_sequence(self, sequence):
        atomic_write(self.__get_filename() + ".seq", lz4.block.compress(json.dumps(sequence)))

    def load_payload(self):
        return read_binary_file(self.__get_filename())

    def __str__(self):
        prefix = ""
        if self.node_type == KaflNodeType.regular or self.node_type == KaflNodeType.favorite:
            prefix = "Node: "
        elif self.node_type == KaflNodeType.crash:
            prefix = "Crash: "
        elif self.node_type == KaflNodeType.kasan:
            prefix = "KASan: "
        elif self.node_type == KaflNodeType.timeout:
            prefix = "Timeout: "
        elif self.node_type == KaflNodeType.preliminary:
            prefix = "Preliminary: "
        return prefix + str(self.node_id) + "\n[Level: " + str(self.level) + "]\n" + " t/s\n" + self.identifier

    @classmethod
    def load_json(cls, json_data):
        log_tree("Restoring: " + str(json_data['node_id']))
        obj =  cls(json_data['level'], None, None,
                   node_state=int(json_data['node_state']), node_type=int(json_data['node_type']),
                   current=json_data['current'], write_data=False)
        obj.node_id = int(json_data['node_id'])
        obj.bits = json_data['bits']
        obj.identifier = json_data['identifier']
        obj.payload_len = json_data['payload_len']
        obj.payload_hash = json_data['payload_hash']
        return obj

    @classmethod
    def reset_node_id(cls):
        global KaflNodeID, KaflCrashID, KaflKASanID, KaflTimeoutID
        KaflNodeID = 1
        KaflCrashID = 1
        KaflKASanID = 1
        KaflTimeoutID = 1
        KaflPreliminaryID = 1


class KaflGraph:
    def __init__(self, seed, enabled=True):
        self.enabled = enabled
        if self.enabled:
            import pygraphviz as pgv
            self.file = FuzzerConfiguration().argument_values['work_dir'] + "/graph.dot"
            self.dot = pgv.AGraph(directed=True, strict=True)
            self.dot.graph_attr['epsilon'] = '0.0008'
            self.dot.graph_attr['defaultdist'] = '2'
            self.dot.write(self.file)

            for data in seed:
                self.dot.add_edge(None, str(data))

    def append(self, old, new):
        if self.enabled:
            self.dot.add_edge(str(old), str(new))
            self.update(new)

    def update(self, node):
        if self.enabled:
            if node.node_type == KaflNodeType.regular or node.node_type == KaflNodeType.favorite:
                if node.node_state == KaflNodeState.untouched:
                    self.__set_untouched(node)
                elif node.node_state == KaflNodeState.in_progress:
                    self.__set_in_progress(node)
                elif node.node_state == KaflNodeState.finished:
                    self.__set_finished(node)
            else:
                if node.node_type == KaflNodeType.crash:
                    self.__set_crashed(node)
                elif node.node_type == KaflNodeType.kasan:
                    self.__set_kasan(node)
                elif node.node_type == KaflNodeType.timeout:
                    self.__set_timeout(node)
                elif node.node_type == KaflNodeType.preliminary:
                    self.__set_preliminary(node)

            if node.node_type == KaflNodeType.favorite:
                self.__set_favorite(node)
            else:
                self.__set_regular(node)

            if node.current:
                self.__set_current(node)
            elif not node.current and not node.node_type == KaflNodeType.favorite:
                self.__unset_current(node)

    def __set_favorite(self, node):
        n = self.dot.get_node(str(node))
        n.attr['color'] = 'blue'
        n.attr['penwidth'] = '4.0'

    def __set_regular(self, node):
        n = self.dot.get_node(str(node))
        n.attr['color'] = ''
        n.attr['penwidth'] = '1.0'

    def __set_untouched(self, node):
        n = self.dot.get_node(str(node))
        n.attr['fillcolor'] = 'white'
        n.attr['style'] = 'filled'

    def __set_in_progress(self, node):
        n = self.dot.get_node(str(node))
        n.attr['fillcolor'] = 'yellow'
        n.attr['style'] = 'filled'

    def __set_finished(self, node):
        n = self.dot.get_node(str(node))
        n.attr['fillcolor'] = 'olivedrab1'
        n.attr['style'] = 'filled'

    def __set_finished_cycle(self, node):
        n = self.dot.get_node(str(node))
        n.attr['fillcolor'] = 'green'
        n.attr['style'] = 'filled'

    def __set_crashed(self, node):
        n = self.dot.get_node(str(node))
        n.attr['fillcolor'] = 'red'
        n.attr['style'] = 'filled'

    def __set_kasan(self, node):
        n = self.dot.get_node(str(node))
        n.attr['fillcolor'] = 'orange'
        n.attr['style'] = 'filled'

    def __set_timeout(self, node):
        n = self.dot.get_node(str(node))
        n.attr['fillcolor'] = 'grey'
        n.attr['style'] = 'filled'

    def __set_preliminary(self, node):
        n = self.dot.get_node(str(node))
        n.attr['fillcolor'] = 'beige'
        n.attr['style'] = 'filled'

    def __set_current(self, node):
        n = self.dot.get_node(str(node))
        n.attr['color'] = 'red'
        n.attr['penwidth'] = '4.0'

    def __unset_current(self, node):
        n = self.dot.get_node(str(node))
        n.attr['color'] = ''
        n.attr['penwidth'] = '1.0'

    def draw(self):
        if self.enabled:
            self.dot.write(self.file)

    def remove_node(self, node):
        self.dot.remove_node(self.dot.get_node(str(node)))

class KaflTree:

    MASTER_NODE_ID = -1

    def __init__(self, seed, enable_graphviz=False, flush=True):
        global KaflNodeID

        self.fuzz_yield = fuzz_yield()

        self.qemu_lookup = QemuLookupSet()

        self.level = 0
        self.max_level = 0
        self.cycles = -1
        self.all_nodes = []
        self.references = {}
        self.current = self.MASTER_NODE_ID
        self.random_shuffled = False

        self.favorite_buf = []
        self.favorite_unfinished_buf = []
        self.regular_buf = []
        self.regular_unfinished_buf = []
        self.finished_buf = []

        self.bitmap_size = FuzzerConfiguration().config_values['BITMAP_SHM_SIZE']
        self.depth_search_first = FuzzerConfiguration().config_values["DEPTH-FIRST-SEARCH"]

        self.buckets = [0x0, 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80]

        self.fav_bitmap = []
        self.fav_bitmap_updated = False

        if FuzzerConfiguration().config_values['MAX_MIN_BUCKETS']:
            self.max_bucket_values = []
            self.backup_max_bucket_values = []
            self.max_bucket_ref = []
            self.next_max_bucket = []
            self.old_pending_node = None
            self.max_min_bucketing_enabled = True
        else:
            self.max_min_bucketing_enabled = False


        self.preliminary_mode = False
        self.preliminary_mode_queue = []

        self.bitmap_fd = os.open(FuzzerConfiguration().argument_values['work_dir'] + "/bitmaps/bitmap", os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.crash_bitmap_fd = os.open(FuzzerConfiguration().argument_values['work_dir'] + "/bitmaps/crash_bitmap", os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.kasan_bitmap_fd = os.open(FuzzerConfiguration().argument_values['work_dir'] + "/bitmaps/kasan_bitmap", os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.timeout_bitmap_fd = os.open(FuzzerConfiguration().argument_values['work_dir'] + "/bitmaps/timeout_bitmap", os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.backup_bitmap_fd = os.open(FuzzerConfiguration().argument_values['work_dir'] + "/bitmaps/backup_bitmap", os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.backup_crash_bitmap_fd = os.open(FuzzerConfiguration().argument_values['work_dir'] + "/bitmaps/backup_crash_bitmap", os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.backup_kasan_bitmap_fd = os.open(FuzzerConfiguration().argument_values['work_dir'] + "/bitmaps/backup_kasan_bitmap", os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.backup_timeout_bitmap_fd = os.open(FuzzerConfiguration().argument_values['work_dir'] + "/bitmaps/backup_timeout_bitmap", os.O_RDWR | os.O_SYNC | os.O_CREAT)

        os.ftruncate(self.bitmap_fd, FuzzerConfiguration().config_values['BITMAP_SHM_SIZE'])
        os.ftruncate(self.crash_bitmap_fd, FuzzerConfiguration().config_values['BITMAP_SHM_SIZE'])
        os.ftruncate(self.kasan_bitmap_fd, FuzzerConfiguration().config_values['BITMAP_SHM_SIZE'])
        os.ftruncate(self.timeout_bitmap_fd, FuzzerConfiguration().config_values['BITMAP_SHM_SIZE'])
        os.ftruncate(self.backup_bitmap_fd, FuzzerConfiguration().config_values['BITMAP_SHM_SIZE'])
        os.ftruncate(self.backup_crash_bitmap_fd, FuzzerConfiguration().config_values['BITMAP_SHM_SIZE'])
        os.ftruncate(self.backup_kasan_bitmap_fd, FuzzerConfiguration().config_values['BITMAP_SHM_SIZE'])
        os.ftruncate(self.backup_timeout_bitmap_fd, FuzzerConfiguration().config_values['BITMAP_SHM_SIZE'])

        self.bitmap = mmap.mmap(self.bitmap_fd, self.bitmap_size, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        self.crash_bitmap = mmap.mmap(self.crash_bitmap_fd, self.bitmap_size, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        self.kasan_bitmap = mmap.mmap(self.kasan_bitmap_fd, self.bitmap_size, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        self.timeout_bitmap = mmap.mmap(self.timeout_bitmap_fd, self.bitmap_size, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        self.backup_bitmap = mmap.mmap(self.backup_bitmap_fd, self.bitmap_size, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        self.backup_crash_bitmap = mmap.mmap(self.backup_crash_bitmap_fd, self.bitmap_size, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        self.backup_kasan_bitmap = mmap.mmap(self.backup_kasan_bitmap_fd, self.bitmap_size, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        self.backup_timeout_bitmap = mmap.mmap(self.backup_timeout_bitmap_fd, self.bitmap_size, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)

        if flush:
            for i in range(self.bitmap_size):
                self.bitmap[i] = '\x00'
                self.crash_bitmap[i] = '\x00'
                self.kasan_bitmap[i] = '\x00'
                self.timeout_bitmap[i] = '\x00'
        for i in range(self.bitmap_size):
            self.fav_bitmap.append(None)

        if self.max_min_bucketing_enabled:
            for i in range(self.bitmap_size):
                self.max_bucket_values.append(None)
                self.backup_max_bucket_values.append(None)
                self.max_bucket_ref.append(None)

        self.c_bitmap = (c_uint8 * self.bitmap_size).from_buffer(self.bitmap)
        self.c_crash_bitmap = (c_uint8 * self.bitmap_size).from_buffer(self.crash_bitmap)
        self.c_kasan_bitmap = (c_uint8 * self.bitmap_size).from_buffer(self.kasan_bitmap)
        self.c_timeout_bitmap = (c_uint8 * self.bitmap_size).from_buffer(self.timeout_bitmap)

        self.graph = KaflGraph([], enabled=enable_graphviz)
        self.favorites = 0
        self.favorites_in_progress = 0
        self.favorites_finished = 0
        self.paths = 0
        self.paths = len(seed)
        self.paths_in_progress = 0
        self.paths_finished = 0

        self.score_changed = False

        self.payload_hashes = {}

        self.bitmap_native_so = CDLL(os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))) + '/native/bitmap.so')

        for payload, bitmap in seed:
            node = KaflNode(self.level, payload, bitmap, None, node_type=KaflNodeType.favorite)
            self.__append_to_level(node)
            self.favorites += 1

        if self.all_nodes:
            self.current = 0 
        self.__restore_state()
        self.__restore_graph()

        self.sort_default = True
        self.ignore_bit_counts = False

    def __restore_graph(self):
        log_tree("__restore_graph()")
        if self.current != self.MASTER_NODE_ID:
            self.__get_from_ref(self.current).current = True
        for key, value in self.references.items():
            key = int(key)
            for next_key in value:
                next_node = self.all_nodes[next_key]
                if key == self.MASTER_NODE_ID:
                    self.graph.append(None, next_node)
                else:
                    self.graph.append(self.all_nodes[key], next_node)

    def __enable_preliminary_mode(self):
        log_tree("creating bitmap backups...")
        self.bitmap.seek(0)
        self.crash_bitmap.seek(0)
        self.kasan_bitmap.seek(0)
        self.timeout_bitmap.seek(0)
        self.backup_bitmap.seek(0)
        self.backup_crash_bitmap.seek(0)
        self.backup_kasan_bitmap.seek(0)
        self.backup_timeout_bitmap.seek(0)

        self.backup_bitmap.write(self.bitmap.read(self.bitmap_size))
        self.backup_crash_bitmap.write(self.crash_bitmap.read(self.bitmap_size))
        self.backup_kasan_bitmap.write(self.kasan_bitmap.read(self.bitmap_size))
        self.backup_timeout_bitmap.write(self.timeout_bitmap.read(self.bitmap_size))

        self.backup_bitmap.flush()
        self.backup_crash_bitmap.flush()
        self.backup_kasan_bitmap.flush()
        self.backup_timeout_bitmap.flush()

        if self.max_min_bucketing_enabled:
            self.next_max_bucket = []
            for i in range(len(self.max_bucket_values)):
                self.backup_max_bucket_values[i] = self.max_bucket_values[i]

        for e in self.preliminary_mode_queue:
            e.remove()
        self.preliminary_mode_queue = []

        self.qemu_lookup.enable_preliminary_mode()
        self.preliminary_mode = True
        self.graph.update(self.__get_from_ref(self.current))

        return 0

    def __disable_preliminary_mode(self):
        log_tree("restoring bitmaps...")

        self.bitmap.seek(0)
        self.crash_bitmap.seek(0)
        self.kasan_bitmap.seek(0)
        self.timeout_bitmap.seek(0)
        self.backup_bitmap.seek(0)
        self.backup_crash_bitmap.seek(0)
        self.backup_kasan_bitmap.seek(0)
        self.backup_timeout_bitmap.seek(0)

        self.bitmap.write(self.backup_bitmap.read(self.bitmap_size))
        self.crash_bitmap.write(self.backup_crash_bitmap.read(self.bitmap_size))
        self.kasan_bitmap.write(self.backup_kasan_bitmap.read(self.bitmap_size))
        self.timeout_bitmap.write(self.backup_timeout_bitmap.read(self.bitmap_size))

        self.bitmap.flush()
        self.crash_bitmap.flush()
        self.kasan_bitmap.flush()
        self.timeout_bitmap.flush()

        if self.max_min_bucketing_enabled:
            self.next_max_bucket = []
            for i in range(len(self.max_bucket_values)):
                self.max_bucket_values[i] = self.backup_max_bucket_values[i]


        log_tree("flushing preliminary queue...")
        for node in self.preliminary_mode_queue:
            try:
                self.graph.remove_node(node)
            except:
                pass

        log_tree("flushing preliminary qemu map...")
        self.qemu_lookup.disable_preliminary_mode()
        self.preliminary_mode = False
        self.graph.update(self.__get_from_ref(self.current))

        return len(self.preliminary_mode_queue)

    def __get_ref(self, node):
        return self.all_nodes.index(node)

    def __get_from_ref(self, ref):
        return self.all_nodes[ref]

    def __evaluate_favorite(self, new_node):
        if new_node.node_type == KaflNodeType.favorite:
            return

    def __append_to_level(self, new_node):
        if self.current not in self.references.keys():
            self.references[self.current] = []
        self.all_nodes.append(new_node)
        self.references[self.current].append(self.all_nodes.index(new_node))
        if new_node.level > self.max_level:
            self.max_level = new_node.level

        if new_node.node_type == KaflNodeType.favorite:
            self.favorite_buf.append(self.__get_ref(new_node))
        elif new_node.node_type == KaflNodeType.regular and new_node.node_state < KaflNodeState.finished:
            self.regular_buf.append(self.__get_ref(new_node))
        elif new_node.node_state >= KaflNodeState.finished:
            self.finished_buf.append(self.__get_ref(new_node))

        self.payload_hashes[new_node.payload_hash] = self.__get_ref(new_node)

        if self.max_min_bucketing_enabled:
            for i in list(set(self.next_max_bucket)):
                log_tree("===> New max bucket " + str(i) + " = " + str(self.max_bucket_values[i]) + "\tID: "+ str(new_node.node_id))
                old_node = None
                if self.max_bucket_ref[i]:
                    log_tree("Replacing ...")
                    self.old_pending_node = self.max_bucket_ref[i]
                self.max_bucket_ref[i] = new_node 

            self.next_max_bucket = []


    def __change_current(self, new_node):
        if new_node:
            if self.current != self.MASTER_NODE_ID:
                current = self.__get_from_ref(self.current)
                current.current = False
                self.graph.update(current)
            self.current = self.__get_ref(new_node)
            new_node.current = True
            self.level = new_node.level
            self.graph.update(new_node)

    def __set_finished(self, node):
        if node:
            if node.node_state != KaflNodeState.finished:
                self.paths_finished += 1
                if node.node_type == KaflNodeType.favorite:
                    self.favorites_finished += 1

            if node.node_state == KaflNodeState.in_progress:
                self.paths_in_progress -= 1 
                if node.node_type == KaflNodeType.favorite:
                    self.favorites_in_progress -= 1

            node.node_state = KaflNodeState.finished
            self.finished_buf.append(self.__get_ref(node))
            self.graph.update(node)

    def __set_unfinished(self, node):
        if node:
            node.node_state = KaflNodeState.in_progress
            self.paths_in_progress += 1
            if node.node_type == KaflNodeType.favorite:
                self.favorites_in_progress += 1
            
            if node.node_type == KaflNodeType.favorite:
                self.favorite_unfinished_buf.append(self.__get_ref(node))
            else:
                self.regular_unfinished_buf.append(self.__get_ref(node))
            self.graph.update(node)

    def __restore_state(self):
        self.favorite_buf = []
        for node in self.all_nodes:
            if node.node_type == KaflNodeType.favorite and node.node_state == KaflNodeState.untouched:
                self.favorite_buf.append(self.__get_ref(node))

        self.favorite_unfinished_buf = []
        for node in self.all_nodes:
            if node.node_type == KaflNodeType.favorite and node.node_state == KaflNodeState.in_progress:
                self.favorite_unfinished_buf.append(self.__get_ref(node))

        self.regular_buf = []
        for node in self.all_nodes:
            if node.node_type == KaflNodeType.regular and node.node_state == KaflNodeState.untouched:
                self.regular_buf.append(self.__get_ref(node))

        self.regular_unfinished_buf = []
        for node in self.all_nodes:
            if node.node_type == KaflNodeType.regular and node.node_state == KaflNodeState.in_progress:
                self.regular_unfinished_buf.append(self.__get_ref(node))

        self.finished_buf = []
        for node in self.all_nodes:
            if node.node_type < KaflNodeType.crash and node.node_state == KaflNodeState.finished:
                self.finished_buf.append(self.__get_ref(node))
        self.cycles += 1
        self.random_shuffled = False

    def __prepare_finished(self):
        if not self.random_shuffled:
            favorite = filter(lambda x: self.__get_from_ref(x).node_type == KaflNodeType.favorite, self.finished_buf)
            regular = filter(lambda x: self.__get_from_ref(x).node_type != KaflNodeType.favorite, self.finished_buf)
            random.shuffle(favorite)
            random.shuffle(regular)
            self.finished_buf = favorite + regular
            self.random_shuffled = True

    def __get_favorites(self):
        if not (self.favorite_buf or self.favorite_unfinished_buf):
            return None
        self.random_shuffled = False
        if self.favorite_buf:
            if self.depth_search_first:
                next_node = self.__get_from_ref(self.favorite_buf.pop(len(self.favorite_buf)-1))
            else:
                next_node = self.__get_from_ref(self.favorite_buf.pop())
        else:
            next_node = self.__get_from_ref(self.favorite_unfinished_buf.pop(-1))
            self.__set_finished(next_node)
        self.__change_current(next_node)
        return next_node

    def __get_regular(self):
        if not (self.regular_buf or self.regular_unfinished_buf):
            return None
        self.random_shuffled = False
        if self.regular_buf:
            if self.depth_search_first:
                next_node = self.__get_from_ref(self.regular_buf.pop(len(self.regular_buf)-1))
            else:
                next_node = self.__get_from_ref(self.regular_buf.pop())
        else:
            next_node = self.__get_from_ref(self.regular_unfinished_buf.pop(-1))
            self.__set_finished(next_node)
        self.__change_current(next_node)
        return next_node

    def __get_finished(self):
        if not self.finished_buf:
            return None
        self.__prepare_finished()
        if self.depth_search_first:
            next_node = self.__get_from_ref(self.finished_buf.pop(len(self.finished_buf)-1))
        else:
            next_node = self.__get_from_ref(self.finished_buf.pop())
        self.__change_current(next_node)
        return next_node

    def get_current(self):
        if self.current != self.MASTER_NODE_ID:
            return self.__get_from_ref(self.current)
        else:
            return self.all_nodes[0]

    def get_next(self, performance, finished=False):
        tmp = self.__get_from_ref(self.current)

        if self.current != self.MASTER_NODE_ID:
            if tmp.node_state != KaflNodeState.finished:
                if finished:
                    self.__set_finished(self.__get_from_ref(self.current))
                else:
                    self.__set_unfinished(self.__get_from_ref(self.current))
        

        next_node = self.__get_favorites()
        if not next_node:
            if RAND(20) == 0:
                next_node = self.__get_regular()
            else:
                next_node = self.__get_finished()
        if not next_node:
            self.__restore_state()
            return self.get_next(performance)
        self.draw()

        log_tree("log_tree: " + str(self.__get_score(self.__get_ref(next_node))) + " " + str(next_node.fav_bits) + " " + str(next_node.new_bit_count) + " " + str(next_node.level) + " " + str(next_node.performance))
        return next_node

    def __is_favorite(self, node):
        for i in node.bits:
            if not self.fav_bitmap[i]:
                self.fav_bitmap[i] = self.__get_ref(node)
                self.fav_bitmap_updated = True


    def __check_if_max_bucket(self, value, field):
        if (self.max_bucket_values[field] == None) or value > self.max_bucket_values[field]:
            log_tree("=====>>> " + str(value) + " vs " + str(self.max_bucket_values[field]) + "\t" + str(field))
            self.max_bucket_values[field] = value

            self.next_max_bucket.append(field)
            if self.preliminary_mode:
                log_tree("Max bucket found (v: " + str(value) + " @ " + str(field) + ")... [preliminary]")
            else:
                log_tree("Max bucket found (v: " + str(value) + " @ " + str(field) + ")...")

            return True
        return False

    def __are_new_bits_present(self, new_bitmap):
        self.bitmap_native_so.are_new_bits_present.restype = c_uint64
        result =  self.bitmap_native_so.are_new_bits_present(self.c_bitmap, (c_uint8 * self.bitmap_size).from_buffer_copy(new_bitmap), c_uint64(self.bitmap_size))
        # byte_count, bit_count
        return (result >> 32), (result & 0xFFFFFFFF)
    def __is_finding_unique(self, bitmap, finding_bitmap, timeout=False):
        self.bitmap_native_so.is_finding_unique.restype = c_bool
        return self.bitmap_native_so.is_finding_unique(finding_bitmap, (c_uint8 * self.bitmap_size).from_buffer_copy(bitmap), c_uint64(self.bitmap_size))

    def __check_if_favorite(self, node):

        prevs = []
        if node.node_type > KaflNodeType.favorite:
            return

        for i in node.bits:
            if (self.fav_bitmap[i]):

                if(self.max_min_bucketing_enabled and node != self.max_bucket_ref[i]) or not self.max_min_bucketing_enabled:
                    prev = self.__get_from_ref(self.fav_bitmap[i])
                    if prev == node:
                        continue

                    if not self.ignore_bit_counts:
                        if not (node.bits >= prev.bits and node.fav_factor < prev.fav_factor): 
                            continue
                    else:
                        if node.fav_factor > prev.fav_factor: 
                            continue

                    prevs.append(prev)
                    prev.fav_bits -= 1

            node.fav_bits += 1
            self.fav_bitmap[i] = self.__get_ref(node)
            self.score_changed = True
            
        if self.score_changed:
            self.score_changed = False
            self.reevalute_favorite(prevs)
                
            self.favorites += 1

            self.regular_buf.remove(self.__get_ref(node))

            if node.performance == 0 or (1/node.performance) <= 1000.0:
                self.favorite_buf.insert(0,self.__get_ref(node))
            else:
                self.favorite_buf.append(self.__get_ref(node))

            node.node_type = KaflNodeType.favorite
            self.graph.update(node)  

    def __get_score(self, id):
        node = self.__get_from_ref(id)
        if node.performance == 0:
            return (0)
    
        if 1/node.performance >= 150:
            perf = 1
        else:
            perf = 0
        if self.sort_default:
            return (perf,  node.fav_bits, -node.level,-node.fav_factor)
        else:
            return (perf, -node.level, node.fav_bits, 1/node.performance)


    def resort_favs(self):
        self.favorite_buf = sorted(self.favorite_buf, key=self.__get_score)


    def toggle_preliminary_mode(self, state):
        if state and not self.preliminary_mode:
            return self.__enable_preliminary_mode()
        elif not state and self.preliminary_mode:
            return self.__disable_preliminary_mode()
        return 0

    def reevalute_favorite(self, prevs):
        for prev in list(set(prevs)):
            if prev.level == 0:
                continue
            reference = self.__get_ref(prev)
            if reference not in self.fav_bitmap:
                self.favorites -= 1
                if prev.node_state == KaflNodeState.in_progress:
                    self.favorites_in_progress -= 1
                if prev.node_state == KaflNodeState.finished:
                    self.favorites_finished -= 1

                if reference in self.favorite_buf:
                    self.favorite_buf.remove(reference)
                    self.regular_buf.append(reference)
                if reference in self.favorite_unfinished_buf:
                    self.favorite_unfinished_buf.remove(reference)
                    self.regular_unfinished_buf.append(reference)

                prev.node_type = KaflNodeType.regular
                self.graph.update(prev)  


    def __is_unique_crash(self, bitmap):
        return self.__is_finding_unique(bitmap, self.c_crash_bitmap, timeout=True)

    def __is_unique_kasan(self, bitmap):
        return self.__is_finding_unique(bitmap, self.c_kasan_bitmap, timeout=True)

    def __is_unique_timeout(self, bitmap):
        empty_bitmap = True
        for i in range(len(bitmap)):
            if bitmap[i] != '\xff':
                empty_bitmap = False 
                break
        if empty_bitmap:
            log_tree("Very suspicious...kAFL bitmap is empty.\n\t\tWrong address range configured or buggy userspace agent in use?\n\n")

        return self.__is_finding_unique(bitmap, self.c_timeout_bitmap, timeout=True)

    def __check_if_duplicate(self, payload):
        if mmh3.hash(payload) in self.payload_hashes:
            return True
        return False

    def append(self, payload, bitmap, methode, node_state=None, node_type=None, performance=0.0):
        accepted = False

        new_byte_count = 0
        new_bit_count = 0

        if self.preliminary_mode:
            found = False
            if node_type >= KaflNodeType.crash:
                if node_type == KaflNodeType.crash:
                    accepted = self.__is_unique_crash(bitmap)
                elif node_type == KaflNodeType.kasan:
                    accepted = self.__is_unique_kasan(bitmap)
                elif node_type == KaflNodeType.timeout:
                    accepted = self.__is_unique_timeout(bitmap)
            else:
                new_byte_count, new_bit_count = self.__are_new_bits_present(bitmap)
                if new_bit_count != 0 and not self.__check_if_duplicate(payload):
                    accepted = True

            if accepted:
                log_tree("new preliminary input found: " + repr(payload[:32]))
                new_node = KaflNode((self.level + 1), payload, bitmap, methode, node_state=KaflNodeState.untouched, node_type=KaflNodeType.preliminary, performance=performance)
                self.preliminary_mode_queue.append(new_node)
                self.graph.append(self.__get_from_ref(self.current), new_node)
                self.draw()
                return True
            return False

        if node_type:
            if node_type >= KaflNodeType.crash:
                if node_type == KaflNodeType.crash:
                    accepted = self.__is_unique_crash(bitmap)
                elif node_type == KaflNodeType.kasan:
                    accepted = self.__is_unique_kasan(bitmap)
                elif node_type == KaflNodeType.timeout:
                    accepted = self.__is_unique_timeout(bitmap)
                if not accepted:
                    return False

        if not accepted:
            new_byte_count, new_bit_count = self.__are_new_bits_present(bitmap)
            found = (new_bit_count != 0)
            if self.__check_if_duplicate(payload):
                return False
            if found:
                if not node_type >=KaflNodeType.crash:
                    self.paths += 1
                accepted = True

        if accepted:
            if self.__check_if_duplicate(payload):
                return False

            log_tree("new input found: " + repr(payload[:32]))
            new_node = KaflNode((self.level + 1), payload, bitmap, methode, node_state=node_state, node_type=node_type, performance=performance, new_byte_count=new_byte_count, new_bit_count=new_bit_count)
            if methode:
                self.fuzz_yield.append_result(methode)
                self.fuzz_yield.write_result(FuzzerConfiguration().argument_values['work_dir'] + "/yield.txt")
            self.__append_to_level(new_node)
            self.graph.append(self.__get_from_ref(self.current), new_node)
            if not node_type >=KaflNodeType.crash:
                self.__check_if_favorite(new_node)
                self.__is_favorite(new_node)
                if self.max_min_bucketing_enabled and self.old_pending_node:
                    self.__is_favorite(self.old_pending_node)
                    self.old_pending_node = None
            self.draw()
            return True
        else:
            return False

    def get_bitmap_values(self):
        count_bytes = 0
        bits_per_byte = 0
        for e in self.bitmap:
            if e != '\x00':
                count_bytes += 1
                for b in (self.buckets):
                    if ord(e) >= b+1:
                        bits_per_byte += 1

        ratio_coverage = 100.0 * (float(count_bytes) / float(self.bitmap_size))
        if count_bytes != 0:
            ratio_bits = float(bits_per_byte)/float(count_bytes)
        else:
            ratio_bits = 0.0
        return ratio_coverage, ratio_bits


    def draw(self):
        self.graph.draw()

    def get_num_of_untouched_nodes(self):
        try:
            return len(self.references[self.current])
        except KeyError:
            return 0

    def save_data(self):
        return
        ignore = [  "bitmap_fd", 
                    "crash_bitmap_fd", 
                    "kasan_bitmap_fd",
                    "timeout_bitmap_fd", 
                    "bitmap", 
                    "crash_bitmap", 
                    "kasan_bitmap", 
                    "timeout_bitmap",
                    "backup_bitmap_fd", 
                    "backup_crash_bitmap_fd", 
                    "backup_kasan_bitmap_fd",
                    "backup_timeout_bitmap_fd", 
                    "backup_bitmap", 
                    "backup_crash_bitmap", 
                    "backup_kasan_bitmap", 
                    "backup_timeout_bitmap"]
        dump = {}
        for key, value in self.__dict__.iteritems():
            if key != 'graph' and key not in ignore:
                dump[key] = value

        with open(FuzzerConfiguration().argument_values['work_dir'] + "/tree.json", 'w') as outfile:
            json.dump(dump, outfile, default=json_dumper)

    @classmethod
    def load_data(cls, enable_graphviz=False):
        log_tree("Restore from json file...")
        obj = cls([], enable_graphviz=enable_graphviz, flush=False)
        KaflNode.reset_node_id()
        with open(FuzzerConfiguration().argument_values['work_dir'] + "/tree.json", 'r') as infile:
            dump = json.load(infile)
            for key, value in dump.iteritems():
                if key == 'all_nodes':
                    obj.all_nodes = []
                    for var in value:
                        obj.all_nodes.append(KaflNode.load_json(var))
                else:
                    setattr(obj, key, value)
        obj.__restore_graph()
        return obj
