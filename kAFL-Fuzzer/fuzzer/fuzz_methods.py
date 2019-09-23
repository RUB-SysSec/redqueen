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
from collections import namedtuple
from common.util import atomic_write

METHODE_UNKOWN =			0
METHODE_REDQUEEN =			1
METHODE_SE =				2
METHODE_BITFLIP_8 =			3
METHODE_BITFLIP_16 =		4
METHODE_BITFLIP_32 =		5
METHODE_ARITHMETIC_8 =		6
METHODE_ARITHMETIC_16 =		7
METHODE_ARITHMETIC_32 =		8
METHODE_INTERESTING_8 =		9
METHODE_INTERESTING_16 =	10
METHODE_INTERESTING_32 =	11
METHODE_HAVOC =				12
METHODE_SPLICING =			13
METHODE_RADAMSA =			14
METHODE_IMPORT =			15
METHODE_DICT_BF =			16


METHODS_NUM =				17

methods = {
	METHODE_UNKOWN:			"unknown       ",
	METHODE_REDQUEEN:		"redqueen      ",
	METHODE_SE:				"se            ",
	METHODE_BITFLIP_8:		"bitflip-8     ",
	METHODE_BITFLIP_16:		"bitflip-16    ",
	METHODE_BITFLIP_32:		"bitflip-32    ",
	METHODE_ARITHMETIC_8:	"arithmetic-8  ",
	METHODE_ARITHMETIC_16:	"arithmetic-16 ",
	METHODE_ARITHMETIC_32:	"arithmetic-32 ",
	METHODE_INTERESTING_8:	"interesting-8 ",
	METHODE_INTERESTING_16:	"interesting-16",
	METHODE_INTERESTING_32:	"interesting-32",
	METHODE_HAVOC:			"havoc         ",
	METHODE_SPLICING:		"splicing      ",
	METHODE_RADAMSA:		"radamsa       ",
	METHODE_IMPORT:			"import        ",
	METHODE_DICT_BF:		"dict-bf       ",
}

class fuzz_yield:
	def __init__(self):
		global METHODS_NUM
		self.methods = {}
		for i in range(METHODS_NUM):
			self.methods[i] = 0

	def append_result(self, methode):
		self.methods[methode.get_type()] += 1

	def write_result(self, file):
		global METHODS_NUM, methods
		output = ""
		for i in range(METHODS_NUM):
			if(self.methods[i] > 0):
				output += methods[i] + ":\t" + str(self.methods[i]) + "\n" 
		atomic_write(file, output)

class fuzz_methode:
	def __init__(self, methode_type=METHODE_UNKOWN, redqueen_cmp=None, input_byte=None, bb_delta=0):
		self.methode_type = methode_type
		self.redqueen_cmp = redqueen_cmp
		self.input_byte = input_byte
		self.bb_delta = bb_delta

	def save_to_file(self, workdir_path, preliminary_id, preliminary=False):
		if preliminary:
			f = open((workdir_path + "/yield/preliminary/" + "/yield-" + str(preliminary_id)), "w")
		else:
			f = open((workdir_path + "/yield/corpus/" + "/yield-" + str(preliminary_id)), "w")
		f.write(json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4))
		f.close()

	def read_from_file(self, workdir_path, preliminary_id, preliminary=False):
		try:
			if preliminary:
				f = open((workdir_path + "/yield/preliminary/" + "/yield-" + str(preliminary_id)))
			else:
				f = open((workdir_path + "/yield/corpus/" + "/yield-" + str(preliminary_id))) 
			obj = json.loads(f.read(), object_hook=lambda d: namedtuple('X', d.keys())(*d.values()))
			self.methode_type = obj.methode_type
			self.redqueen_cmp = obj.redqueen_cmp
			self.input_byte = obj.input_byte
			self.bb_delta = obj.bb_delta
			f.close()
		except Exception as e: 
			logger(e)

	def get_type(self):
		return self.methode_type

	def get_fuzz_methode_str(self):
		global methods
		return methods[self.methode_type]
