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

class FuzzingResult:
    def __init__(self, pos, crash, timeout, kasan, affected_bytes, slave_id, performance, methode, bitmap_hash, reloaded=False, new_bits=True, qid=0):
        self.pos = pos
        self.crash = crash
        self.timeout = timeout
        self.kasan = kasan
        self.affected_bytes = affected_bytes
        self.slave_id = slave_id
        self.reloaded = reloaded
        self.performance = performance
        self.new_bits = new_bits
        self.qid = qid
        self.methode = methode
        self.bitmap_hash = bitmap_hash

KAFL_TAG_REQ =              0
KAFL_TAG_JOB =              1
KAFL_TAG_OUTPUT =           2
KAFL_TAG_START =            3
KAFL_TAG_RESULT =           4
KAFL_TAG_MAP_INFO =         5
KAFL_TAG_NXT_FIN =          6
KAFL_TAG_NXT_UNFIN =        7
KAFL_TAG_UNTOUCHED_NODES =  8
KAFL_TAG_REQ_BITMAP =       9
KAFL_TAG_REQ_EFFECTOR =     10
KAFL_TAG_GET_EFFECTOR =     11
KAFL_INIT_BITMAP =          12
KAFL_TAG_REQ_SAMPLING =     13
KAFL_TAG_REQ_BENCHMARK =    14
KAFL_TAG_ABORT_REQ =        15
KAFL_TAG_REQ_REDQUEEN =     16
KAFL_TAG_REDQUEEN_RESULT =  17
KAFL_TAG_REDQUEEN_SYNC =    18
KAFL_TAG_REQ_BITMAP_HASH =  19
KAFL_TAG_REQ_PRELIMINARY =  20

KAFL_TAG_REQ_VERIFY =       21
KAFL_TAG_REQ_VERIFY_SYNC =  22

KAFL_TAG_REQ_PING =         23
KAFL_TAG_UPDATE_REDQUEEN =  24
