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

import socket
import select
from common.debug import logger

INTR_ERRNO = 4

def safe_select(rlist, wlist, xlist, timeout):
	global INTR_ERRNO
	rvalue = None
	while True:
		try:
			rvalue = select.select(rlist, wlist, xlist, timeout)
			break
		except select.error as e:
			if e.args[0] == INTR_ERRNO:
				continue
			else:
				raise
	return rvalue

class safe_socket(socket.socket):
	def __init__(self, family):
		super(safe_socket, self).__init__(family)

	def connect(self, address):
		global INTR_ERRNO
		while True:
			try:
				super(safe_socket, self).connect(address)
				break
			except OSError as e:
				if e.args[0] == INTR_ERRNO:
					continue
				else:
					raise

	def settimeout(self, value):
		global INTR_ERRNO
		while True:
			try:
				super(safe_socket, self).settimeout(value)
				break
			except OSError as e:
				if e.args[0] == INTR_ERRNO:
					continue
				else:
					raise

	def setblocking(self, flag):
		global INTR_ERRNO
		while True:
			try:
				super(safe_socket, self).setblocking(flag)
				break
			except OSError as e:
				if e.args[0] == INTR_ERRNO:
					continue
				else:
					raise

	def send(self, data):
		global INTR_ERRNO
		rvalue = None
		while True:
			try:
				rvalue = super(safe_socket, self).send(data)
			except OSError as e:
				if e.args[0] == INTR_ERRNO:
					continue
				else:
					raise
		return rvalue

	def recv(self, size):
		global INTR_ERRNO
		rvalue = None
		while True:
			try:
				rvalue = super(safe_socket, self).recv(size)
			except (OSError,IOError) as e:
				if e.args[0] == INTR_ERRNO or e.errno == errno.EINTR:
					continue
				else:
					raise
		return rvalue

	def close(self):
		global INTR_ERRNO
		rvalue = None
		while True:
			try:
				rvalue = super(safe_socket, self).close()
			except OSError as e:
				if e.args[0] == INTR_ERRNO:
					continue
				else:
					raise
		return rvalue