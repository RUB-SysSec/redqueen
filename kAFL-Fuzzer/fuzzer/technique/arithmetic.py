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

from array import array
from fuzzer.technique.helper import *
from common.debug import log_master
import ctypes

__author__ = 'sergej'


def arithmetic_range(data, skip_null=False, effector_map=None, set_arith_max=None):
    if len(data) == 0:
        return 0

    if not set_arith_max:
        set_arith_max = AFL_ARITH_MAX

    data_len = len(data)
    num = 0

    if effector_map:
        byte_count = 0
        for i in range(len(data)):
            if effector_map[i]:
                byte_count += 1
                num += (set_arith_max*2)
                if byte_count >= 2:
                    num += ((set_arith_max-2)*4)
                if byte_count >= 4:
                    num += ((set_arith_max-2)*4)

            else:
                byte_count = 0
    else:
        num += (data_len*(set_arith_max*2))

        if data_len > 1:
                num += ((data_len-1)*((set_arith_max-2)*4))
        if data_len > 2:
                num += ((data_len-3)*((set_arith_max-2)*4))

    return num


def mutate_seq_8_bit_arithmetic_array(data, func, skip_null=False, kafl_state=None, effector_map=None, set_arith_max=None):
    if kafl_state:
        kafl_state["technique"] = "ARITH 8"

    if not set_arith_max:
        set_arith_max = AFL_ARITH_MAX

    for i in range(0, len(data)):
        if effector_map:
            if not effector_map[i]:
                continue
        if skip_null and data[i] == 0x00:
            func(None, no_data=True)
            func(None, no_data=True)
            continue

        func(None, no_data=True)
        func(None, no_data=True)
        for j in range(1,set_arith_max+1):
            r = data[i] ^ (data[i] + j)
            if is_not_bitflip(ctypes.c_uint8(r).value):
                data[i] = (data[i] + j) & 0xff
                func(data.tostring())
                data[i] = (data[i] - j) & 0xff
            else:
                func(None, no_data=True)

            r = data[i] ^ (data[i] - j)
            if is_not_bitflip(ctypes.c_uint8(r).value):
                data[i] = (data[i] - j) & 0xff
                func(data.tostring())
                data[i] = (data[i] + j) & 0xff
            else:
                func(None, no_data=True)


def mutate_seq_16_bit_arithmetic_array(data, func, skip_null=False, kafl_state=None, effector_map=None, set_arith_max=None):
    if kafl_state:
        kafl_state["technique"] = "ARITH 16"

    if not set_arith_max:
        set_arith_max = AFL_ARITH_MAX

    for i in range(0, len(data)-1):
        value = array('H', (data[i:i+2]).tostring())
        value = in_range_16(value[0])
        if effector_map:
            if not( effector_map[i] or effector_map[i+1]):
                continue
        if skip_null and value == 0x00:
            func(None, no_data=True)
            func(None, no_data=True)
            func(None, no_data=True)
            func(None, no_data=True)
            continue
        for j in range(1, set_arith_max+1):

            r1 = (value ^ in_range_16(value + j))
            r2 = (value ^ in_range_16(value - j))
            r3 = value ^ swap_16(swap_16(value) + j)
            r4 = value ^ swap_16(swap_16(value) - j)

            if is_not_bitflip(r1) and ((value & 0xff) + j) > 0xff:
                func(data[:i].tostring() + to_string_16(in_range_16(value + j)) + data[i+2:].tostring())
            else:
                func(None, no_data=True)

            # little endian decrement
            if is_not_bitflip(r2) and (value & 0xff) < j:
                func(data[:i].tostring() + to_string_16(in_range_16(value - j)) + data[i+2:].tostring())
            else:
                func(None, no_data=True)

            # big endian increment
            if is_not_bitflip(r3) and ((value >> 8) + j) > 0xff:
                func(data[:i].tostring() + to_string_16(swap_16(in_range_16(swap_16(value) + j))) + data[i+2:].tostring())
            else:
                func(None, no_data=True)

            # big endian decrement
            if is_not_bitflip(r4) and (value >> 8) < j:
                func(data[:i].tostring() + to_string_16(swap_16(in_range_16(swap_16(value) - j))) + data[i+2:].tostring())
            else:
                func(None, no_data=True)


def mutate_seq_32_bit_arithmetic_array(data, func, skip_null=False, kafl_state=None, effector_map=None, set_arith_max=None):
    if kafl_state:
        kafl_state["technique"] = "ARITH 32"

    if not set_arith_max:
        set_arith_max = AFL_ARITH_MAX

    for i in range(0, len(data)-3):
        value = array('I', (data[i:i+4]).tostring())
        value = in_range_32(value[0])

        if effector_map:
            if not (effector_map[i] or effector_map[i + 1] or effector_map[i + 2] or effector_map[i + 3]):
                continue

        if skip_null and value == 0x00:
            func(None, no_data=True)
            func(None, no_data=True)
            func(None, no_data=True)
            func(None, no_data=True)
            continue
        for j in range(1, set_arith_max+1):


            r1 = (value ^ in_range_32(value + j))
            r2 = (value ^ in_range_32(value - j))
            r3 = value ^ swap_32(swap_32(value) + j)
            r4 = value ^ swap_32(swap_32(value) - j)

            # little endian increment
            if is_not_bitflip(r1) and in_range_32((value & 0xffff) + j) > 0xffff:
                func(data[:i].tostring() + to_string_32(in_range_32(value + j)) + data[i+4:].tostring())
            else:
                func(None, no_data=True)

            # little endian decrement
            if is_not_bitflip(r2) and in_range_32(value & 0xffff) < j:
                func(data[:i].tostring() + to_string_32(in_range_32(value - j)) + data[i+4:].tostring())
            else:
                func(None, no_data=True)

            # big endian increment
            if is_not_bitflip(r3) and in_range_32((swap_32(value) & 0xffff) +j) >0xffff:
                func(data[:i].tostring() + to_string_32(swap_32(in_range_32(swap_32(value) + j))) + data[i+4:].tostring())
            else:
                func(None, no_data=True)

            # big endian decrement
            if is_not_bitflip(r4) and (swap_32(value) & 0xffff) < j:
                func(data[:i].tostring() + to_string_32(swap_32(in_range_32(swap_32(value) - j))) + data[i+4:].tostring())
            else:
                func(None, no_data=True)
