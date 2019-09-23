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

#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define KVM_VMX_PT_SUPPORTED	_IO(KVMIO,	0xe4)

int main(){
	int kvm, ret;

	kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm == -1){
		printf("ERROR: KVM is not loaded!\n");
		exit(1);
	} 

	ret = ioctl(kvm, KVM_VMX_PT_SUPPORTED, NULL);
	if (ret == -1){
		printf("ERROR: KVM-PT is not loaded!\n");
		exit(2);
	}
	if (ret == -2){
		printf("ERROR: Intel PT is not supported on this CPU!\n");
		exit(3);
	}
	printf("KVM-PT is ready!\n");
	return 0;
}
