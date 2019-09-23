/* 
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
*/

#define _GNU_SOURCE

#include <sys/mman.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "../../kafl_user.h"

int __libc_start_main(int (*main) (int,char **,char **),
		      int argc,char **ubp_av,
		      void (*init) (void),
		      void (*fini)(void),
		      void (*rtld_fini)(void),
		      void (*stack_end)) {

    hprintf("LD_PRELOAD hprintf :)\n");

    char filename[256];
    void* info_buffer = mmap((void*)NULL, INFO_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(info_buffer, 0xff, INFO_SIZE);

    hprintf("LD_PRELOAD hprintf :)\n");    
  	hprintf("Own pid is %d\n", getpid());

  	snprintf(filename, 256, "/proc/%d/maps", getpid());
  	hprintf("proc filename: %s\n", filename);

  	FILE* f = fopen(filename, "r");
  	uint16_t len = fread(info_buffer, 1, INFO_SIZE, f);
  	fclose(f);

  	((char*)info_buffer)[len] = '\0';

 	  hprintf("Transfer data to hypervisor\n");

    kAFL_hypercall(HYPERCALL_KAFL_INFO, (uintptr_t)info_buffer);

    return 0;
}
