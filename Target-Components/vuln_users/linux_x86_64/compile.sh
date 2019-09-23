# 
# This file is part of Redqueen.
#
# Sergej Schumilo, 2019 <sergej@schumilo.de> 
# Cornelius Aschermann, 2019 <cornelius.aschermann@rub.de> 
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with Redqueen.  If not, see <http://www.gnu.org/licenses/>.
#
mkdir bin/ 2> /dev/null

gcc src/vuln.c -m64 -D STDIN_INPUT -g -o bin/vuln_stdin_64 
gcc src/vuln.c -m32 -D STDIN_INPUT -g -o bin/vuln_stdin_32  

gcc src/vuln.c -m32 -D STDIN_INPUT -g -fsanitize=address -o bin/vuln_stdin_32_asan
gcc src/vuln.c -m64 -D STDIN_INPUT -g -fsanitize=address -o bin/vuln_stdin_64_asan

gcc src/vuln.c -m64 -D FILE_INPUT -g -o bin/vuln_file_64  
gcc src/vuln.c -m32 -D FILE_INPUT -g -o bin/vuln_file_32 

gcc src/loop.c -m64 -D STDIN_INPUT -g -o bin/loop_stdin_64 
gcc src/loop.c -m32 -D STDIN_INPUT -g -o bin/loop_stdin_32  
gcc src/loop.c -m64 -D FILE_INPUT -g -o bin/loop_file_64  
gcc src/loop.c -m32 -D FILE_INPUT -g -o bin/loop_file_32 
