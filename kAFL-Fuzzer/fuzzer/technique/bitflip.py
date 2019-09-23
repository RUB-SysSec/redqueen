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

__author__ = 'sergej'
from common.debug import log_master

def bitflip_range(data, skip_null=False, effector_map=None):
    if len(data) == 0:
        return 0

    if effector_map:
        effector_map = effector_map[:len(data)]
        data_len = sum(x is True for x in effector_map)
        data_tmp = ""
        for i in range(len(data)):
            if effector_map[i]:
                data_tmp += data[i]
    else:
        data_len = len(data)
        data_tmp = data
    num = data_len*8
    num += data_len*7
    num += data_len*5
    num += data_len
    if effector_map:
        byte_count = 0
        for i in range(len(data)):
            if effector_map[i]:
                byte_count += 1
                if byte_count >= 2:
                    num += 1
                if byte_count >= 4:
                    num += 1

            else:
                byte_count = 0
    else:
        if data_len > 1:
            num += data_len - 1
        if data_len > 3:
            num += data_len - 3
    return num

def bitflip8_range(data, skip_null=False, effector_map=None):
    if effector_map:
        effector_map = effector_map[:len(data)]
        data_len = sum(x is True for x in effector_map)
        data_tmp = ""
        for i in range(len(data)):
            if effector_map[i]:
                data_tmp += data[i]
    else:
        data_len = len(data)
        data_tmp = data
    num = data_len*8
    return num

def mutate_seq_walking_bits_array(data, func, skip_null=False, kafl_state=None, effector_map=None):
    if kafl_state:
        if skip_null:
            kafl_state["technique"] = "BIT-FLIP 1 S0"
        else:
            kafl_state["technique"] = "BIT-FLIP 1"

    for i in xrange(len(data)*8):
        if effector_map:
            if not effector_map[i/8]:
                continue
        if data[i/8] == 0x00 and skip_null:
            func(None, no_data=True)
            continue
        data[i/8] ^= (0x80 >> (i % 8))
        func(data.tostring(), affected_bytes=[0])
        data[i/8] ^= (0x80 >> (i % 8))

def mutate_seq_two_walking_bits_array(data, func, skip_null=False, kafl_state=None, effector_map=None):
    if kafl_state:
        if skip_null:
            kafl_state["technique"] = "BIT-FLIP 2 S0"
        else:
            kafl_state["technique"] = "BIT-FLIP 2"

    for i in range((len(data)*8)-1):
        if effector_map:
            if not (effector_map[i/8] or effector_map[(i+1)/8]):
                continue
        if data[i/8] == 0x00 and data[(i+1)/8] == 0x00 and skip_null:
            func(None, no_data=True)
            continue
        data[i/8] ^= (0x80 >> (i % 8))
        data[(i+1)/8] ^= (0x80 >> ((i+1) % 8))
        func(data.tostring(), affected_bytes=[0])
        data[i/8] ^= (0x80 >> (i % 8))
        data[(i+1)/8] ^= (0x80 >> ((i+1) % 8))

def mutate_seq_four_walking_bits_array(data, func, skip_null=False, kafl_state=None, effector_map=None):
    if kafl_state:
        if skip_null:
            kafl_state["technique"] = "BIT-FLIP 4 S0"
        else:
            kafl_state["technique"] = "BIT-FLIP 4"

    for i in range( (len(data)*8-3) ):
        if effector_map:
            if not (effector_map[i/8] or effector_map[(i+3)/8]):
                continue
        if data[i/8] == 0x00 and data[(i+3)/8] == 0x00 and skip_null:
            func(None, no_data=True)
            continue

        data[i/8] ^= (0x80 >> (i % 8))
        data[(i+1)/8] ^= (0x80 >> ((i+1) % 8))
        data[(i+2)/8] ^= (0x80 >> ((i+2) % 8))
        data[(i+3)/8] ^= (0x80 >> ((i+3) % 8))
        #func(data.tostring(), affected_bytes=[i/8,(i+3)/8])
        func(data.tostring(), affected_bytes=[0])
        data[i/8] ^= (0x80 >> (i % 8))
        data[(i+1)/8] ^= (0x80 >> ((i+1) % 8))
        data[(i+2)/8] ^= (0x80 >> ((i+2) % 8))
        data[(i+3)/8] ^= (0x80 >> ((i+3) % 8))

def mutate_seq_walking_byte_array(data, func, skip_null=False, kafl_state=None, effector_map=None):
    if kafl_state:
        if skip_null:
            kafl_state["technique"] = "BIT-FLIP 8 S0"
        else:
            kafl_state["technique"] = "BIT-FLIP 8"

    for i in range((len(data))):
        if effector_map:
            if not effector_map[i]:
                continue
        if data[i] == 0x00 and skip_null:
            func(None, no_data=True)
            continue
        data[i] ^= 0xFF
        func(data.tostring(), affected_bytes=[i])
        data[i] ^= 0xFF

def mutate_seq_two_walking_bytes_array(data, func, kafl_state=None, effector_map=None):
    if kafl_state:
        kafl_state["technique"] = "BIT-FLIP 16"

    if len(data) > 1:
        for i in range(1, ((len(data)))):
            if effector_map:
                if not (effector_map[i] or effector_map[i-1]):
                    continue
            data[i] ^= 0xFF
            data[i-1] ^= 0xFF
            func( data.tostring(), affected_bytes=[0] )
            data[i] ^= 0xFF
            data[i-1] ^= 0xFF

def mutate_seq_four_walking_bytes_array(data, func, kafl_state=None, effector_map=None):
    if kafl_state:
        kafl_state["technique"] = "BIT-FLIP 32"

    if len(data) > 3:
        for i in range(3, (len(data))):
            if effector_map:
                if not (effector_map[i] or effector_map[i-1] or effector_map[i-2] or effector_map[i-3]):
                    continue
            data[i-0] ^= 0xFF
            data[i-1] ^= 0xFF
            data[i-2] ^= 0xFF
            data[i-3] ^= 0xFF
            func(data.tostring(), affected_bytes=[0])
            data[i-0] ^= 0xFF
            data[i-1] ^= 0xFF
            data[i-2] ^= 0xFF
            data[i-3] ^= 0xFF
