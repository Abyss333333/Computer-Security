#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "lib/encoding.h"
#define keySize 80


int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];//hellos
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	int secLen = strlen(secret_hex);
	const char * issuer_ = urlEncode(issuer);
	int issLen = strlen(issuer_);
	const char * accName_ = urlEncode(accountName);
	int accLen = strlen(accName_);

	int b32Size = keySize/5;
	int qrCodeLen = 128+ b32Size + issLen + accLen;
	uint8_t *res; // for base32 encoding

	char qrCode[qrCodeLen];

	assert (secLen <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);


	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	char * ref = "0123456789ABCDEF";
	int arrSize = keySize/8;
	int appSize = keySize/4;

	uint8_t hex8 [(arrSize)];
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
	//printf("%d\n", hex8);
	res = (uint8_t*) malloc(sizeof(uint8_t)*(b32Size));
	base32_encode(hex8,secLen, res, b32Size);

	sprintf(qrCode, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accName_, issuer_, res);



	displayQRcode(qrCode);

	return (0);
}
