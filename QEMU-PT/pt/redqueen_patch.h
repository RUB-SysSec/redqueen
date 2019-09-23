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

#ifndef __GUARD_REDQUEEN_PATCH__
#define __GUARD_REDQUEEN_PATCH__

#include "qemu/osdep.h"
#include <linux/kvm.h>
#include "pt/patcher.h"

void pt_enable_patches(patcher_t *self);

void pt_disable_patches(patcher_t *self);
#endif
