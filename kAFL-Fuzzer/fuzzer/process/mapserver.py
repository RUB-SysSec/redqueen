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

import mmh3, base64, lz4
import collections

import traceback

from fuzzer.communicator import send_msg, recv_msg, Communicator
from fuzzer.protocol import *
from fuzzer.state import GlobalState
from fuzzer.tree import *
from common.config import FuzzerConfiguration
from common.debug import log_mapserver
from common.qemu import qemu
from fuzzer.fuzz_methods import METHODE_IMPORT

__author__ = 'Sergej Schumilo'

class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


def mapserver_loader(comm):
    log_mapserver("PID: " + str(os.getpid()))

    mapserver_process = MapserverProcess(comm)
    try:
        mapserver_process.loop()
    except KeyboardInterrupt:
        mapserver_process.comm.slave_termination.value = True
        mapserver_process.treemap.save_data()
        mapserver_process.save_data()
        log_mapserver("Date saved!")


class MapserverProcess:
    def __init__(self, comm, initial=True):

        self.comm = comm
        #self.state = MapserverState()
        self.state = GlobalState()


        self.hash_set = set()
        self.preliminary_set = set()


        self.hash_list = set()
        self.crash_list = []
        self.shadow_map = set()

        self.last_hash = ""
        self.post_sync_master_tag = None

        self.effector_map = []
        self.new_findings = 0

        self.redqueen_sync = False

        self.effector_initial_bitmap = None
        self.effector_sync = False
        self.performance = 0

        self.post_sync = False
        self.pre_sync = False
        self.verification_sync = False
        self.round_counter = 0

        self.round_counter_redqueen_sync = 0
        self.round_counter_effector_sync = 0
        self.round_counter_master_post = 0
        self.round_counter_master_pre = 0
        self.round_counter_verification_sync = 0

        self.config = FuzzerConfiguration()
        self.enable_graphviz = self.config.argument_values['g']

        self.abortion_threshold = self.config.config_values['ABORTION_TRESHOLD']

        self.preliminary_mode = False

        self.ring_buffers = []
        for e in range(self.config.argument_values['p']):
            self.ring_buffers.append(collections.deque(maxlen=30))

        if self.config.load_old_state:
            self.load_data()
            self.treemap = KaflTree.load_data(enable_graphviz=self.enable_graphviz)
        else:
            msg = recv_msg(self.comm.to_mapserver_queue)
            self.state["pending"] = len(msg.data)
            self.treemap = KaflTree(msg.data, enable_graphviz=self.enable_graphviz)

    def __save_ring_buffer(self, slave_id, target):
        if "block" in dir(lz4):
            data = []
            for payload in self.ring_buffers[slave_id]:
                data.append(base64.b64encode(payload))
            with open(target, 'w') as outfile:
                outfile.write(lz4.block.compress(json.dumps(data)))
            

    def __check_hash(self, new_hash, bitmap, payload, crash, timeout, kasan, slave_id, reloaded, performance, qid, pos, methode):
        self.ring_buffers[slave_id].append(str(payload))
        
        if self.preliminary_mode:
            hash_was_new = True

        else:
            hash_was_new = False
            if new_hash != self.last_hash:
                if len(self.hash_list) == 0:
                    hash_was_new = True
                if new_hash not in self.hash_list and new_hash not in self.shadow_map:
                    hash_was_new = True


        if crash or kasan or timeout:
            if crash:
                state_str = "crash"
                node_type = KaflNodeType.crash
            elif kasan:
                state_str = "kasan"
                node_type = KaflNodeType.kasan
            elif timeout:
                state_str = "timeout"
                node_type = KaflNodeType.timeout


            if self.treemap.append(payload, bitmap, methode, node_type=node_type):
                if not self.preliminary_mode:
                    log_mapserver("Unique " + state_str + " submited by slave #" + str(slave_id) + " ...")
                    self.__save_ring_buffer(slave_id, self.config.argument_values['work_dir'] +  "/rbuf/" + state_str + "_" + str(self.state[state_str + "_unique"]) + ".rbuf")
                    self.state[state_str] += 1
                    self.state[state_str + "_unique"] += 1
                else:
                    self.state["preliminary"] += 1
                    log_mapserver("Unique " + state_str + " submited by slave #" + str(slave_id) + " [preliminary]...")
            else:
                if not self.preliminary_mode:
                    self.state[state_str] += 1
                    path = FuzzerConfiguration().argument_values['work_dir'] + "/findings/non_uniq/"+ state_str+ "_non_uniq_" + str(self.state[state_str])
                    with open(path , "w") as f:
                        f.write(payload)
                    with open(FuzzerConfiguration().argument_values['work_dir']+"/evaluation/findings.csv",'ab') as f:
                        f.write("%s\n"%json.dumps([time.time()-GlobalState().values["inittime"], path] ))

        elif hash_was_new:
            if self.treemap.append(payload, bitmap, methode, performance=performance):
                if not self.preliminary_mode:
                    if methode.get_type() == METHODE_IMPORT:
                         self.state["imports"] += 1
                    self.hash_list.add(new_hash)
                    self.new_findings += 1
                    self.state["last_hash_time"] = time.time()
                    self.__update_state()
                else:
                    self.state["preliminary"] += 1
            else:
                if not self.preliminary_mode:
                    self.shadow_map.add(new_hash)

        if reloaded:
            self.ring_buffers[slave_id].clear()

    def __update_state(self):
        self.state["ratio_coverage"], self.state["ratio_bits"] = self.treemap.get_bitmap_values()
        self.state["cycles"] = self.treemap.cycles
        self.state["hashes"] = self.treemap.paths
        self.state["path_pending"] = self.treemap.paths - self.treemap.paths_finished - self.treemap.paths_in_progress
        self.state["path_unfinished"] = self.treemap.paths_in_progress
        
        self.state["favorites"] = self.treemap.favorites
        self.state["fav_pending"] = self.treemap.favorites-self.treemap.favorites_finished - self.treemap.favorites_in_progress
        self.state["fav_unfinished"] = self.treemap.favorites_in_progress

    def __post_sync_handler(self):
        if self.round_counter_master_post == self.round_counter:
            self.treemap.resort_favs()
            if self.post_sync_master_tag == KAFL_TAG_NXT_UNFIN:
                data = self.treemap.get_next(self.performance, finished=False)
            else:
                data = self.treemap.get_next(self.performance, finished=True)

            self.__update_state()
            self.state["level"] = data.level + 1
            if self.state["level"] > self.state["max_level"]:
                self.state["max_level"] = self.state["level"]
            state = data.node_state


            if state == KaflNodeState.in_progress or state == KaflNodeState.finished:
                send_msg(KAFL_TAG_NXT_UNFIN, data, self.comm.to_master_from_mapserver_queue)
            else:
                send_msg(KAFL_TAG_NXT_FIN, data, self.comm.to_master_from_mapserver_queue)

            self.round_counter = 0
            return True
        return False

    def __pre_sync_handler(self):
        log_mapserver("__pre_sync_handler: " + str(self.round_counter_master_pre ) + " / " + str(self.round_counter))
        if (self.round_counter_master_pre == self.round_counter):# or self.abortion_alredy_sent:
            send_msg(KAFL_TAG_UNTOUCHED_NODES, self.treemap.get_num_of_untouched_nodes(),
                     self.comm.to_master_from_mapserver_queue)
            return True
        return False

    def __effector_sync_handler(self):
        if (self.round_counter_effector_sync == self.round_counter):
            send_msg(KAFL_TAG_GET_EFFECTOR, self.effector_map, self.comm.to_master_from_mapserver_queue)
            return True
        return False

    def __redqueen_sync_handler(self):
        if (self.round_counter_redqueen_sync == self.round_counter):
            send_msg(KAFL_TAG_REDQUEEN_SYNC, 0, self.comm.to_master_from_mapserver_queue)
            return True
        return False

    def __verification_sync_handler(self):
        log_mapserver("__verificatiom_sync_handler: " + str(self.round_counter_verification_sync ) + " / " + str(self.round_counter))
        if (self.round_counter_verification_sync == self.round_counter):
            send_msg(KAFL_TAG_REQ_VERIFY_SYNC, 0, self.comm.to_master_from_mapserver_queue)
            return True
        return False

    def __result_tag_handler(self, request):
        self.comm.slave_locks_B[request.source].acquire()

        results = request.data
        payloads = []
        bitmaps = []
        payload_shm = self.comm.get_mapserver_payload_shm(request.source)
        bitmap_shm = self.comm.get_bitmap_shm(request.source)
        bitmap_hashes = []

        for result in results:
            if result.new_bits and result.bitmap_hash and result.bitmap_hash:

                bitmap_shm.seek(result.pos * self.comm.get_bitmap_shm_size())
                payload_shm.seek(result.pos * self.comm.get_mapserver_payload_shm_size())
                length = payload_shm.read(4)
                data_len = (ord(length[3]) << 24) + (ord(length[2]) << 16) + (ord(length[1]) << 8) + (ord(length[0]))
                payloads.append(payload_shm.read(data_len))
                bitmaps.append(bitmap_shm.read(self.comm.get_bitmap_shm_size()))
                bitmap_hashes.append(result.bitmap_hash)

            else:
                payloads.append(None)
                bitmaps.append(None)
                bitmap_hashes.append(None)
        self.comm.slave_locks_A[request.source].release()
        for i in range(len(results)):

            if bitmap_hashes[i] is not None and results[i].new_bits:

                self.__check_hash(bitmap_hashes[i], bitmaps[i], payloads[i], results[i].crash, results[i].timeout, results[i].kasan, results[i].slave_id, results[i].reloaded, results[i].performance, results[i].qid, results[i].pos, results[i].methode)
                self.last_hash = bitmap_hashes[i]
                self.round_counter += 1
                if self.effector_initial_bitmap:
                    if self.effector_initial_bitmap != bitmap_hashes[i]:
                        for j in results[i].affected_bytes:
                            log_mapserver("affected_bytes: " + str(j))
                            if not self.effector_map[j]:
                                self.effector_map[j] = True
            else:
                self.round_counter += 1


    def __next_tag_handler(self, request):
        self.post_sync_master_tag = request.tag
        self.post_sync = True
        self.round_counter_master_post = request.data[0]
        self.performance = request.data[1]
        log_mapserver("Performance: " + str(self.performance))

    def __pre_abort_tag_handler(self, request):
        self.round_counter_master_pre = request.data
        self.pre_sync = True

    def __post_abort_tag_handler(self, request):
        self.round_counter_master_post = self.round_counter_master_pre + request.data
        self.pre_sync = False

    def __untouched_tag_handler(self, request):
        self.round_counter_master_pre = request.data
        self.pre_sync = True

    def __req_effector_tag_handler(self, request):
        log_mapserver("New Effector Map (" + str(len(request.data)) + ")")
        self.effector_initial_bitmap = mmh3.hash64(request.data)
        for i in range(self.config.config_values['PAYLOAD_SHM_SIZE']):
            self.effector_map.append(False)

    def __get_effector_tag_handler(self, request):
        self.round_counter_effector_sync = request.data
        self.effector_sync = True

    def __fin_redqueen_tag_handler(self, request):
        self.round_counter_redqueen_sync = request.data
        self.redqueen_sync = True

    def __fin_verification_tag_handler(self, request):
        log_mapserver("__fin_verification_tag_handler: " + str(request.data))
        self.round_counter_verification_sync = request.data        
        self.verification_sync = True

    def __fin_preliminary_tag_handler(self, request):
        # Todo flush shadow map 
        if self.preliminary_mode != request.data:
            self.preliminary_mode = request.data
            if self.preliminary_mode:
                self.state["preliminary"] = 0
            self.last_hash = ""
            log_mapserver("Preliminary Mode: " + str(self.preliminary_mode))

        send_msg(KAFL_TAG_REQ_PRELIMINARY, self.treemap.toggle_preliminary_mode(request.data), self.comm.to_master_from_mapserver_queue)

    def __sync_handler(self):
        if self.redqueen_sync:
            if self.__redqueen_sync_handler():
                self.redqueen_sync = False
                self.round_counter = 0

        if self.effector_sync:
            if self.__effector_sync_handler():
                self.effector_sync = False
                self.effector_initial_bitmap = None
                self.effector_map = []

        if self.verification_sync:
            if self.__verification_sync_handler():
                self.verification_sync = False

        if self.pre_sync:
            if self.__pre_sync_handler():
                self.pre_sync = False
                self.round_counter_master_pre = 0
                log_mapserver("ShadowMap Size: " + str(len(self.shadow_map)))

        if self.post_sync:
            if self.__post_sync_handler():
                self.post_sync = False
                self.round_counter_master_post = 0
                self.round_counter = 0

    def loop(self):
        while True:
            self.__sync_handler()
            request = recv_msg(self.comm.to_mapserver_queue)

            if request.tag == KAFL_TAG_RESULT:
                self.__result_tag_handler(request)
            elif request.tag == KAFL_TAG_NXT_FIN or request.tag == KAFL_TAG_NXT_UNFIN:
                self.__next_tag_handler(request)
            elif request.tag == KAFL_TAG_UNTOUCHED_NODES:
                self.__untouched_tag_handler(request)
            elif request.tag == KAFL_TAG_REQ_EFFECTOR:
                self.__req_effector_tag_handler(request)
            elif request.tag == KAFL_TAG_GET_EFFECTOR:
                self.__get_effector_tag_handler(request)
            elif request.tag == KAFL_TAG_REDQUEEN_SYNC: 
                self.__fin_redqueen_tag_handler(request)
            elif request.tag == KAFL_TAG_REQ_PRELIMINARY:
                self.__fin_preliminary_tag_handler(request)
            elif request.tag == KAFL_TAG_REQ_VERIFY_SYNC:
                self.__fin_verification_tag_handler(request)


    def save_data(self):
        return
        """
        Method to store an entire master state to JSON file...
        """

        dump = {}

        for key, value in self.__dict__.iteritems():
            if key == "state":
                dump[key] = self.state.save_data()
            elif key == "enable_graphviz" or key == "last_hash":
                dump[key] = self.enable_graphviz
            elif key == "hash_list" or key == "shadow_map":
                tmp = []
                for e in value:
                    tmp.append(e)
                dump[key] = tmp


        with open(self.config.argument_values['work_dir'] + "/mapserver.json", 'w') as outfile:
            json.dump(dump, outfile, default=json_dumper, cls=SetEncoder, indent=4)

    def load_data(self):
        """
        Method to load an entire master state from JSON file...
        """
        with open(FuzzerConfiguration().argument_values['work_dir'] + "/mapserver.json", 'r') as infile:
            dump = json.load(infile)
            for key, value in dump.iteritems():
                if key == "hash_list" or key == "shadow_map":
                    tmp = set()
                    for e in value:
                        tmp.add(tuple(e))
                    setattr(self, key, tmp)
                elif key == "state":
                    tmp = MapserverState()
                    tmp.load_data(value)
                    setattr(self, key, tmp)
                else:
                    setattr(self, key, value)
