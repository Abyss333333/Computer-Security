#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <math.h>
#include "lib/sha1.h"
#define keySize 80


void generateSecKey(char * secret_hex, uint8_t *hex8) {

int secLen = strlen(secret_hex);
char * ref = "0123456789ABCDEF";
int arrSize = keySize/8;
int appSize = keySize/4;
//uint8_t hex8 [(arrSize)];
int hexArray[secLen];
int paddingLen = 0;
int targetLen = secLen;

if (secLen < appSize) {
		paddingLen  = appSize - secLen;
		targetLen = appSize;
		secLen = appSize;
	}

	int i, it;

	for (i = 0; i < paddingLen; i++){
		hexArray[i] = 0;
	}

	for ( i= paddingLen; i < targetLen; i ++ ){
		char d_C = secret_hex[i - paddingLen];
		hexArray[i] = -1;
		for (it = 0; it< 16; it++){
			char cap = toupper(d_C);
			if(cap == ref[it]){
				hexArray[i] = it;
				break;
			}
		}
	}

	int pos = 0;

	for (i=0; i< secLen; i += 2){
		int mod = (i+2) % 2;
		if (mod == 0){
			int a1 = (hexArray[i] <<4)&0x0f0;
			int a2 = ((hexArray[i+1])&0x0f)&0x0ff;
			hex8[pos] = a1 + a2;
			pos ++ ;
		}
	}

	//result = hex8;




}





static int
validateTOTP(char * secret_hex, char * TOTP_string)
{	
	int secLen = strlen(secret_hex);
	int appSize = keySize/8;
	uint8_t hex8 [(appSize)];
	generateSecKey(secret_hex, hex8);
	int i;


	
	int block_len = 512/8;
	uint8_t hashBlock [block_len];
	for (i=0; i< block_len; i++){
		hashBlock[i] =0;
		if(i< appSize){
			hashBlock[i] = hex8[i];
		}
	}

	uint8_t hashBlock_outer[block_len];
	uint8_t hashBlock_inner[block_len];
	memset(hashBlock_inner,0,block_len);
	memset(hashBlock_outer,0,block_len);
	for (i=0; i< block_len; i++){
		hashBlock_inner[i] =(hashBlock[i] ^ 0x36);
		hashBlock_outer[i] = (hashBlock[i]^ 0x5c);
	}
	

	

	uint8_t x[8];

	time_t secs = time(NULL);
	uint64_t timeX = ((int)secs - 0) /30;

	
	
	for (i=7; i >=0; i--){
		x[i] = (uint8_t)(timeX & 0xff) ;
		timeX >>= 8;
	}

	// SHA 

	int shaLen = 160;
	int shaSize = 20;

	uint8_t res[SHA1_DIGEST_LENGTH];
	uint8_t sha[SHA1_DIGEST_LENGTH];

	SHA1_INFO x1,x2;
	sha1_init(&x1);
	sha1_init(&x2);

	sha1_update(&x2, hashBlock_inner, block_len);
	sha1_update(&x2, x, 8);
	sha1_final(&x2, sha);

	sha1_update(&x1, hashBlock_outer, block_len);
	sha1_update(&x1, sha, SHA1_DIGEST_LENGTH);
	sha1_final(&x1, res);

	int bias = res[19] & 0xf;
	int y = ((res[bias] & 0x7f) << 24)|
		((res[bias+1] & 0xff) << 16)|
		((res[bias+2] & 0xff) << 8)|
		(res[bias+3] & 0xff);
	
	int TOTPnum = y % 1000000;
	//char TOTP_prediction [7];
	//sprintf(TOTP_prediction, "%d", TOTPnum);
	//printf("TOTP prediction %s\n", TOTP_prediction);
	
	return TOTPnum == atoi(TOTP_string);
}


int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];
	


	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	


	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
