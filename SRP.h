#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

#include "t_sha.h"

#include "Storm.h"

#define SHA_DIGESTSIZE 20

//VS17 redefinitions
#define strncpy strncpy_s
#define _strupr _strupr_s

typedef void * BigBuffer;

#pragma region "Unrelated to the actual Storm Class"
unsigned char *MakeSessionKey(unsigned char *dest,
	unsigned char*data,
	unsigned int length);

void displayArray(BYTE *array, int length)
{
	for (int i = 0; i < length; i++)
		printf("%02x ", array[i]);
	printf("\n\n");
}
/*
 * The interleaved session-key hash.  This separates the even and the odd
 * bytes of the input (ignoring the first byte if the input length is odd),
 * hashes them separately, and re-interleaves the two outputs to form a
 * single 320-bit value.
 */
unsigned char *MakeSessionKey(unsigned char *key,
	unsigned char *sk,
	unsigned int sklen)
{
	unsigned int i, klen;
	unsigned char *hbuf;
	unsigned char hout[SHA_DIGESTSIZE];
	SHA1_CTX ctxt;

	if (!sklen)
		return NULL;

	while (key && !*sk)
	{
		sk++;
		key--;
	}

	if (sklen == 1)
	{
		sk++;
		sklen--;
	}

	klen = sklen >> 1;

	if (!(hbuf = (unsigned char *)malloc(klen * sizeof(char))))
		return NULL;

	memset(hbuf, 0, klen);

	if (klen)
	{
		for (i = 0; i < klen; ++i)
			hbuf[i] = sk[i * 2];
	}

	SHA1Init(&ctxt);
	SHA1Update(&ctxt, hbuf, klen);
	SHA1Final(hout, &ctxt);

	for (i = 0; i < sizeof(hout); ++i)
		key[i * 2] = hout[i];

	if (klen)
	{
		for (i = 0; i < klen; ++i)
			hbuf[i] = sk[2 * i + 1];
	}

	SHA1Init(&ctxt);
	SHA1Update(&ctxt, hbuf, klen);
	SHA1Final(hout, &ctxt);

	for (i = 0; i < sizeof(hout); ++i)
		key[2 * i + 1] = hout[i];

	free(hbuf);
	return key;
}
#pragma endregion

class BnSRP
{
private:
	Storm *mStorm = Storm::Instance();

public:
	BnSRP();
	//BnSRP(char *Storm);
	virtual ~BnSRP();

	void MakeAuth(void *Buf);
	void MakeProof(void *Buf,
		const char *User,
		const char *Pass,
		void *Salt,
		void *PubKey);

	void GetX(void *clienthash, void *salt);
	void GenerateVerifyFromSalt(const char *User, const char *Pass, void *Salt, void *v);
	void MakeCreate(const char *User, const char *Pass, void *salt_out, void *v_out);
private:
	void HashAccount(void *Buf, const char *User, const char *Pass);
	void GenerateSalt(void *Buf);

	void InitVars();
	BYTE *GenKey(BYTE *data);

	SHA1_CTX TotalCtx;
	HMODULE hStorm;

	BigBuffer Generator;
	BigBuffer Modulus;
	BigBuffer PrivKey;
	BigBuffer PubKeyA;
	BYTE SessionKey[40];
};
