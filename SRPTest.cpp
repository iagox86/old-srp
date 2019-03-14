#include <stdio.h>
#include <stdlib.h>

#include "SRP.h"

//    	byte []salt = new byte[]    { 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4 };
//    	byte []pubKeyB = new byte[] { 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8 };

//BYTE salt[32] = { 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4 };
//BYTE pubKeyB[32] = { 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8, 5, 6, 7, 8 };


int main(int argc, char *argv[])
{
	//Init the storm class ##########################
	Storm *InitializedStormClass = Storm::Instance();
	//###############################################
	
	//############################################### <Account creation initial Salt + Verifier>
	char Username[] = "Srp3Test"; //
	char Password[] = "asdfasdf";
	BYTE salt[BIGINT_SIZE];
	BYTE verify[BIGINT_SIZE];
	BnSRP *InitialSRP = new BnSRP();
	MakeCreate(Username, Password, salt, verify);
	delete InitialSRP;
	InitialSRP = NULL;
	//############################################### <Continue playing around now that we got our initial values>

	BnSRP *srp = new BnSRP();

	BYTE auth[32];
	memset(auth, 0, 32);
	srp->MakeAuth((BYTE*)auth);

	printf("Authorization: ");
	for(int i = 0; i < 32; i++)
		printf("%02x ", auth[i]);
	printf("\n\n");

	BYTE proof[32];
	memset(proof, 0, 32);
	srp->MakeProof(proof, Username, Password, salt, pubKeyB);

	printf("Proof: ");
	for(int i = 0; i < 32; i++)
		printf("%02x ", proof[i]);
	printf("\n\n");

	delete srp;

	//destroy the storm class #######################
	Storm::Release();
	InitializedStormClass = NULL;
	//###############################################
	system("pause");

	return 0;
}
