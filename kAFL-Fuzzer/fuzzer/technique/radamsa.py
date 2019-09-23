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

__author__ = 'sergej'

import subprocess
from common.config import FuzzerConfiguration
import uuid
import os
from common.debug import logger
import shutil
import socket
import time
import glob
import random

def radamsa_range(perf_score):

	max_iterations = int(perf_score * 2.5)

	if max_iterations < AFL_HAVOC_MIN:
		max_iterations = AFL_HAVOC_MIN

 	return max_iterations

def execute(cmd):
	logger("CMD: " + cmd)
	proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True)
	return proc

location_corpus = FuzzerConfiguration().argument_values['work_dir'] + "/corpus/"


def mutate_seq_radamsa_array(data, func, max_iterations, kafl_state=None):
	if kafl_state:
		kafl_state["technique"] = "RADAMSA"

	logger("FILES: " + str(len(os.listdir(location_corpus))))
	files = sorted(glob.glob(location_corpus+"*"))
	last_n = 5
	rand_n = 5
	samples = files[-last_n:] + random.sample( files[:-last_n], max(0, min( rand_n, len(files)-last_n) ) )
	try:
		if samples:
			proc = execute("./fuzzer/technique/radamsa -o :21337 -n inf " + " ".join(samples) )

			while True:
				try:
					s = socket.create_connection(("127.0.0.1", 21337), timeout=1)
					s.recv(1)
					break
				except Exception as e: 
					logger(str(e))
					time.sleep(0.1)
				finally:
					try:
						s.close()	
					except:
						pass

			for i in range(max_iterations):
				s = socket.create_connection(("127.0.0.1", 21337))
				payload = s.recv(65530)
				s.close()
				size = len(payload)

				if size > (64<<10):
					payload = payload[:(2<<10)]
				if size == 0:
					func(data.tostring())
				else:
					func(payload[:(2<<10)])

			proc.kill()
			proc.wait()
	except:
		pass
