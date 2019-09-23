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

#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char** argv){

#ifdef STDIN_INPUT
	char input[256];
	memset(input, 0x00, 256);
	size_t len = read(STDIN_FILENO, input, 256);
#elif FILE_INPUT
	if(argc != 2){
		return 0; 
	}

	int fd = open(argv[1], O_RDONLY);

	char input[256];
	memset(input, 0x00, 256);
	size_t len = read(fd, input, 256);
#endif


	if(len >= 256){
		return 0;
	}

	char* array = malloc(128);


	if(input[0] == 'K')
		if(input[1] == 'E')
			if(input[2] == 'R')
				if(input[3] == 'N')
					if(input[4] == 'E')
						if(input[5] == 'L')
							if(input[6] == 'A')
								if(input[7] == 'F')
									if(input[8] == 'L')
										assert(false);

	if(input[0] == 'S')
		if(input[1] == 'E')
			if(input[2] == 'R')
				if(input[3] == 'G')
					if(input[4] == 'E')		
						if(input[5] == 'J')
							assert(false);

	if(input[0] == 'K'){
    	if(input[1] == 'A'){
        	if(input[2] == 'S'){
            	if(input[3] == 'A'){
                	if(input[4] == 'N'){
						free(array);
						array[0] = 234;
					}
				}
        	}
        }
	}
	free(array);
	return 0;
}	
