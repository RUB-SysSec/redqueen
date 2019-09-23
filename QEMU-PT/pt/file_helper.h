/* 
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
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

//doesn't take ownership of path, num_addrs or addrs
void parse_address_file(char* path, size_t* num_addrs, uint64_t** addrs);

//doesn't take ownership of buf
void write_re_result(char* buf);

//doesn't take ownership of buf
void write_se_result(char* buf);

//doesn't take ownership of buf
void write_trace_result(char* buf);

//doesn' take ownership of buf
void write_debug_result(char* buf);

void delete_redqueen_files(void);

void delete_trace_files(void);
