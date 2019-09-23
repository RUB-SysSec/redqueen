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
set -e

if [[ "$OSTYPE" == "linux-gnu" ]]; then
	printf "\tPrecompiling executables...\n"
	mkdir -p bin/
	mkdir -p bin/fuzzer/
	mkdir -p bin/loader/
	mkdir -p bin/info/

	gcc -c -static -shared -O0 -m32 -Werror -fPIC src/ld_preload_info.c -o bin/ld_preload_info_32.o -ldl
	gcc -c -static -shared -O0 -m64 -Werror -fPIC src/ld_preload_info.c -o bin/ld_preload_info_64.o -ldl

	gcc -c -static -shared -O0 -m32 -Werror -fPIC src/ld_preload_fuzz.c -o bin/ld_preload_fuzz_32.o -ldl
	gcc -c -static -shared -O0 -m64 -Werror -fPIC src/ld_preload_fuzz.c -o bin/ld_preload_fuzz_64.o -ldl

	gcc -c -static -shared -O0 -m32 -Werror -fPIC -DASAN_BUILD src/ld_preload_fuzz.c -o bin/ld_preload_fuzz_32_asan.o -ldl
	gcc -c -static -shared -O0 -m64 -Werror -fPIC -DASAN_BUILD src/ld_preload_fuzz.c -o bin/ld_preload_fuzz_64_asan.o -ldl

	gcc -c -static -O0 -m32 -Werror src/userspace_loader.c -o bin/userspace_loader_32.o
	gcc -c -static -O0 -m64 -Werror src/userspace_loader.c -o bin/userspace_loader_64.o

else
	printf "\tError: Cannont compile linux userspace components on this plattform!\n\tPlease use Linux instead!\n"
fi
