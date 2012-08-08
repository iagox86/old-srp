#include <stdio.h>
#include <stdlib.h>

#include "SRP.h"

//    	byte []salt = new byte[]    { 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4 };
//    	byte []pubKeyB = new byte[] { 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8 };

BYTE salt[32] = { 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4 };
BYTE pubKeyB[32] = { 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8 };


int main(int argc, char *argv[])
{
	BnSRP *srp = new BnSRP("c:\\storm.dll");

	BYTE auth[32];
	memset(auth, 0, 32);
	srp->MakeAuth((BYTE*)auth);

	printf("Authorization: ");
	for(int i = 0; i < 32; i++)
		printf("%02x ", auth[i]);
	printf("\n\n");

	BYTE proof[32];
	memset(proof, 0, 32);
	srp->MakeProof(proof, "iago", "password", salt, pubKeyB);

	printf("Proof: ");
	for(int i = 0; i < 32; i++)
		printf("%02x ", proof[i]);
	printf("\n\n");

	delete srp;

	system("pause");

	return 0;
}