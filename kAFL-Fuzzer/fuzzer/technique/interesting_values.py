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
from fuzzer.technique.helper import *
from array import array
__author__ = 'sergej'


def interesting_range(data, skip_null=False, effector_map=None):

    if effector_map:
        data_len = sum(x is True for x in effector_map)
        data_tmp = ""
        for i in range(len(data)):
            if effector_map[i]:
                data_tmp += data[i]
    else:
        data_len = len(data)
        data_tmp = data
    if skip_null:
        num_of_non_null_bytes = data_len - data_tmp.count('\x00')
        num = num_of_non_null_bytes * len(interesting_8_Bit)
        num += ((num_of_non_null_bytes-1) * (len(interesting_16_Bit)))*2
        num += ((num_of_non_null_bytes-3) * (len(interesting_32_Bit)))*2
    else:
        num = data_len * len(interesting_8_Bit)
        if data_len > 1:
            num += ((data_len-1) * (len(interesting_16_Bit)))*2
	if data_len > 3:
            num += ((data_len-3) * (len(interesting_32_Bit)))*2
    if num < 0:
        return 0
    
    return num


def mutate_seq_8_bit_interesting_array(data, func, skip_null=False, kafl_state=None, effector_map=None):
    if kafl_state:
        kafl_state["technique"] = "INTERST 8"

    for i in range(0, len(data)):
        if effector_map:
            if not effector_map[i]:
                continue
        byte = data[i]
        for j in range(len(interesting_8_Bit)):
            if skip_null and byte == 0:
                continue
            interesting_value = in_range_8(interesting_8_Bit[j])
            if is_not_bitflip(byte ^ interesting_value) and is_not_arithmetic(byte, interesting_value, 1):
                func(data[:i].tostring() + to_string_8(interesting_value) + data[(i+1):].tostring())
            else:
                func(None, no_data=True)
        data[i] = byte

def mutate_seq_16_bit_interesting_array(data, func, skip_null=False, kafl_state=None, effector_map=None, set_arith_max=None):
    if kafl_state:
        kafl_state["technique"] = "INTERST 16"

    for i in range(len(data) - 1):
        if effector_map:
            if not (effector_map[i] or effector_map[i+1]):
                continue

        byte1 = data[i + 1]
        byte2 = data[i]
        value = (byte1 << 8) + byte2
    
        if skip_null and value == 0:
            continue

        for j in range(len(interesting_16_Bit)):
            interesting_value = in_range_16(interesting_16_Bit[j])
            swapped_value = swap_16(interesting_value)

            if is_not_bitflip(value ^ interesting_value) and \
            is_not_arithmetic(value, interesting_value, 2, set_arith_max=set_arith_max) and \
            is_not_interesting(value, interesting_value, 2, 0):
                func(data[:i].tostring() + to_string_16(interesting_value) + data[(i + 2):].tostring())
            else:
                func(None, no_data=True)

            if interesting_value != swapped_value and \
               is_not_bitflip(value ^ swapped_value) and \
               is_not_arithmetic(value, swapped_value, 2, set_arith_max=set_arith_max) and \
               is_not_interesting(value, swapped_value, 2, 1):
                func(data[:i].tostring() + to_string_16(swapped_value) + data[(i+2):].tostring())
            else:
                func(None, no_data=True)

def mutate_seq_32_bit_interesting_array(data, func, skip_null=False, kafl_state=None, effector_map=None, set_arith_max=None):
    if kafl_state:
        kafl_state["technique"] = "INTERST 32"

    for i in range(len(data) - 3):
        if effector_map:
            if not (effector_map[i] or effector_map[i + 1] or effector_map[i + 2] or effector_map[i + 3]):
                continue

        byte1 = data[i + 3]
        byte2 = data[i + 2]
        byte3 = data[i + 1]
        byte4 = data[i + 0]
        value = (byte1 << 24) + (byte2 << 16) + (byte3 << 8) + byte4

        if skip_null and value == 0:
            continue

        for j in range(len(interesting_32_Bit)):
            interesting_value = in_range_32(interesting_32_Bit[j])
            swapped_value = swap_32(interesting_value)
            if is_not_bitflip(value ^ interesting_value) and \
               is_not_arithmetic(value, interesting_value, 4, set_arith_max=set_arith_max) and \
               is_not_interesting(value, interesting_value, 4, 0):
                func(data[:i].tostring() + to_string_32(interesting_value) + data[(i+4):].tostring())
            else:
                func(None, no_data=True)

            if interesting_value != swapped_value  and\
               is_not_bitflip(value ^ swapped_value) and\
               is_not_arithmetic(value, swapped_value, 4, set_arith_max=set_arith_max) and\
               is_not_interesting(value, swapped_value, 4, 1):
                func(data[:i].tostring() + to_string_32(swapped_value) + data[(i+4):].tostring())
            else:
                func(None, no_data=True)
