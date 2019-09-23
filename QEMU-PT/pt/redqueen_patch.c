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

#include "redqueen_patch.h"
#include "redqueen.h"
#include "patcher.h"
#include "file_helper.h"
#include "debug.h"

///////////////////////////////////////////////////////////////////////////////////
// Private Helper Functions Declarations
///////////////////////////////////////////////////////////////////////////////////

void _load_and_set_patches(patcher_t* self);

///////////////////////////////////////////////////////////////////////////////////
// Public Functions
///////////////////////////////////////////////////////////////////////////////////

void pt_enable_patches(patcher_t *self){
  _load_and_set_patches(self);
  patcher_apply_all(self);
}

void pt_disable_patches(patcher_t *self){
  patcher_restore_all(self);
}


///////////////////////////////////////////////////////////////////////////////////
// Private Helper Functions Definitions
///////////////////////////////////////////////////////////////////////////////////


void _load_and_set_patches(patcher_t* self){
  size_t num_addrs = 0;
  uint64_t *addrs = NULL;
  parse_address_file(redqueen_workdir.redqueen_patches, &num_addrs, &addrs);
  if(num_addrs){
    patcher_set_addrs(self, addrs, num_addrs);
    free(addrs);
  }
}
