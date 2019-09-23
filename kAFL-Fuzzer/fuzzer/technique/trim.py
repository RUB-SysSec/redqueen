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

MAX_EXECS = 16
MAX_ROUNDS = 32
MIN_SIZE = 512
APPEND_VALUE = 0.1

APPEND_BYTES = 16 

pow2_values = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768]

def get_pow2_value(value):
	for pow2_value in reversed(pow2_values):
		if pow2_value <= value:
			return pow2_value
	return 1

def perform_trim(size, send_handler, modify_size_handler, error_handler):
	global MAX_ROUNDS, MAX_EXECS, MIN_SIZE, APPEND_BYTES

	if size <= MIN_SIZE: 
		return size

	bitmap = send_handler()
	if error_handler():
		return size
	execs = 0
	new_size = size
	if size == 0:
		return new_size

	for _ in range(MAX_ROUNDS):
		abort = True
		for i in reversed(range(0, pow2_values.index(get_pow2_value(new_size))+1)):
			if pow2_values[i] < new_size:

				execs +=1
				if execs == MAX_EXECS:
					abort = True
					break

				modify_size_handler(new_size-pow2_values[i])
				new_bitmap = send_handler()

				if error_handler():
					return new_size

				if bitmap == new_bitmap:
					new_size -= pow2_values[i]
					abort = False
					break

				if new_size <= MIN_SIZE:
					break

		if abort:
			break

	if new_size < MIN_SIZE:
		new_size = MIN_SIZE
	elif (new_size+int(new_size * APPEND_VALUE)) < size:
		new_size += int(new_size * APPEND_VALUE) 

	new_size += APPEND_BYTES
	modify_size_handler(new_size)
	return new_size