#include "SRP.h"
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

#define GETADDRESS(ord) GetProcAddress(hStorm, (LPCSTR)ord)
#define BSWAP(a,b,c,d) ((((((a << 8) | b) << 8) | c) << 8) | d)

unsigned char *MakeSessionKey(unsigned char *dest,
							  unsigned char*data,
							  unsigned int length);

void displayArray(BYTE *array, int length)
{
	for(int i = 0; i < length; i++)
		printf("%02x ", array[i]);
	printf("\n\n");
}

BnSRP::BnSRP()
{
	exit(1);
}

BnSRP::BnSRP(char *Storm)
{
	InitStorm(Storm);
	InitVars();
}

BnSRP::~BnSRP()
{
	BigDel(this->Modulus);
	BigDel(this->Generator);
	BigDel(this->PrivKey);
	BigDel(this->PubKeyA);

	FreeLibrary(this->hStorm);
}

void BnSRP::InitVars()
{
	static const BYTE ModulusRaw[BIGINT_SIZE] = {	0x87, 0xc7, 0x23, 0x85, 0x65, 0xf6, 0x16, 0x12,
													0xd9, 0x12, 0x32, 0xc7, 0x78, 0x6c, 0x97, 0x7e,
													0x55, 0xb5, 0x92, 0xa0, 0x8c, 0xb6, 0x86, 0x21,
													0x03, 0x18, 0x99, 0x61, 0x8b, 0x1a, 0xff, 0xf8	};

	static const BYTE tempPrivKey[BIGINT_SIZE] = { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };

	static const unsigned int GeneratorRaw = 47;

	BYTE Buf1[SHA_DIGESTSIZE], Buf2[SHA_DIGESTSIZE];
	BYTE Key[BIGINT_SIZE];
	SHA1_CTX ctx;
	
	// generate values
	BigNew(&this->Modulus);
	BigNew(&this->PrivKey);
	BigNew(&this->PubKeyA);
	this->Generator = BigIntegerFromInt(GeneratorRaw);
	this->Modulus = BigIntegerFromBytes(ModulusRaw);
	//this->PrivKey = BigIntegerFromBytes(GenKey(Key));
	this->PrivKey = BigIntegerFromBytes(tempPrivKey);
	printf("The friggin' key is MADE!\n\n\n");
	
	SHA1Init(&ctx);
	SHA1Update(&ctx, ModulusRaw, BIGINT_SIZE);
	SHA1Final(Buf1, &ctx); // Buf1 = H(modulus)
	printf("Original Buf1: ");
	for(int i = 0; i < SHA_DIGESTSIZE; i++)
		printf("%02x ", Buf1[i]);
	printf("\n\n");

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)&GeneratorRaw, 1);
	SHA1Final(Buf2, &ctx); // Buf2 = H(generator)

	printf("Buf2: ");
	for(int i = 0; i < SHA_DIGESTSIZE; i++)
		printf("%02x ", Buf2[i]);
	printf("\n\n");

	printf("Buf1: ");
	for(int i = 0; i < SHA_DIGESTSIZE; ++i)
	{
		Buf1[i] ^= Buf2[i];	// buf1 = H(modulus) xor H(generator)
		printf("%02x ", Buf1[i]);
	}
	printf("\n\n");

	// hash: H(N) xor H(g)
	SHA1Init(&this->TotalCtx);
	SHA1Update(&this->TotalCtx, Buf1, SHA_DIGESTSIZE);

}

bool BnSRP::InitStorm(const char *Storm)
{
	if( !(this->hStorm = LoadLibrary(Storm)) )
		return false;

	BigNew = (SBigNew)GETADDRESS(624);
	BigDel = (SBigDel)GETADDRESS(606);
	BigPowMod = (SBigPowMod)GETADDRESS(628);
	BigFromUnsigned = (SBigFromUnsigned)GETADDRESS(612);
	BigFromBinary = (SBigFromBinary)GETADDRESS(609);
	BigToBinaryBuffer = (SBigToBinaryBuffer)GETADDRESS(638);
	BigAdd = (SBigAdd)GETADDRESS(601);
	BigSub = (SBigSub)GETADDRESS(636);
	BigCompare = (SBigCompare)GETADDRESS(603);
	BigMul = (SBigMul)GETADDRESS(622);

	return true;
}

// returns a 32 byte result in buf
void BnSRP::MakeAuth(void *Buf)
{
	BigPowMod(this->PubKeyA, this->Generator, this->PrivKey, this->Modulus);
	BigIntegerToBytes(this->PubKeyA, Buf);

	printf("PubKeyA: ");
	for(int i = 0; i < 32; i++)
		printf("%02x ", ((BYTE*)Buf)[i]);
	printf("\n");


}

// returns a 20 byte hash
void BnSRP::MakeProof(void *Buf,
					  const char *User,
					  const char *Pass,
					  void *Salt,
					  void *PubKeyB)
{
	char Username[32];
	char Password[32];
	BYTE Hash[SHA_DIGESTSIZE];
	BYTE SessionData[BIGINT_SIZE];
	SHA1_CTX ctx;

	BigBuffer x, v, u, gb; 

	strncpy(Username, User, sizeof(Username) - 1);
	strncpy(Password, Pass, sizeof(Password) - 1);
	_strupr(Username);
	_strupr(Password);
	
	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)Username, (UINT)strlen(Username));
	SHA1Final(Hash, &ctx);

	// Checkpoint number 1
	printf("PROOF #1 (%s) --> ", Username);
	displayArray(Hash, SHA_DIGESTSIZE);



	// hash: (H(N) xor H(g)) | H(U)
	SHA1Update(&this->TotalCtx, Hash, SHA_DIGESTSIZE);
	// hash: (H(N) xor H(g)) | H(U) | s
	SHA1Update(&this->TotalCtx, (BYTE *)Salt, BIGINT_SIZE);

	// compute x = H(s, H(U, ":", P))
	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)Username, (UINT)strlen(Username));
	SHA1Update(&ctx, (BYTE *)":", 1);
	SHA1Update(&ctx, (BYTE *)Password, (UINT)strlen(Password));
	SHA1Final(Hash, &ctx);

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)Salt, BIGINT_SIZE);
	SHA1Update(&ctx, Hash, sizeof(Hash));
	SHA1Final(Hash, &ctx);

	x = BigIntegerFromBytes(Hash, SHA_DIGESTSIZE);

	// compute v = g^x
	v = BigIntegerFromInt(0);
	BigPowMod(v, this->Generator, x, this->Modulus);

	// compute u
	BYTE KeyDataA[BIGINT_SIZE];
	BigIntegerToBytes(this->PubKeyA, KeyDataA);
	
	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)PubKeyB, BIGINT_SIZE);
	SHA1Final(Hash, &ctx); 

	u = BigIntegerFromInt(BSWAP(Hash[0], Hash[1], Hash[2], Hash[3]));

	// unblind g^b (mod N)
	gb = BigIntegerFromBytes(PubKeyB);
	if(BigCompare(gb, v) < 0)
		BigAdd(gb, gb, this->Modulus);
	BigSub(gb, gb, v);

	BigDel(v);

	// compute gb^(a + ux) (mod N)
	BigBuffer e = BigIntegerFromInt(0);
	BigMul(e, x, u); // e = ux
	BigAdd(e, e, this->PrivKey); // e = a + ux
    
	BigDel(u);
	BigDel(x);

	BigBuffer S = BigIntegerFromInt(0);
	BigPowMod(S, gb, e, this->Modulus); // gb^(a + ux)

	BigDel(e);
	BigDel(gb);

	// hash: (H(N) xor H(g)) | H(U) | s | A
	SHA1Update(&this->TotalCtx, KeyDataA, BIGINT_SIZE);
	// hash: (H(N) xor H(g)) | H(U) | s | A | B
	SHA1Update(&this->TotalCtx, (BYTE *)PubKeyB, BIGINT_SIZE);

	BigIntegerToBytes(S, SessionData);
	::MakeSessionKey(this->SessionKey, SessionData, BIGINT_SIZE);
	BigDel(S);

	// hash: (H(N) xor H(g)) | H(U) | s | A | B | K
	SHA1Update(&this->TotalCtx, this->SessionKey, sizeof(this->SessionKey));

	// put final hash in buffer
	SHA1Final((BYTE *)Buf, &this->TotalCtx);
}

BigBuffer BnSRP::BigIntegerFromBytes(const void *Buf, DWORD Len)
{
	BigBuffer BigInt;

	BigNew(&BigInt);
	BigFromBinary(BigInt, Buf, Len);

	return BigInt;
}

void BnSRP::BigIntegerToBytes(BigBuffer BigInt, void *Buf, DWORD Len)
{
	BigToBinaryBuffer(BigInt, Buf, Len, &Len);
}

BigBuffer BnSRP::BigIntegerFromInt(DWORD num)
{
	BigBuffer BigInt;
	
	BigNew(&BigInt);
	BigFromUnsigned(BigInt, num);

	return BigInt;
}

BYTE *BnSRP::GenKey(BYTE *data)
{
	UINT outpos = 0, randcnt = 0, size = BIGINT_SIZE;
	BYTE randout[SHA_DIGESTSIZE], randpool[SHA_DIGESTSIZE];
	SHA1_CTX ctxt;

	memset(randout, 0, sizeof(randout));
	memset(randpool, 0, sizeof(randpool));
	
	srand((unsigned)time(NULL));

	while(size > outpos)
	{
		if(outpos > 0)
		{
			memcpy(data, randout + (sizeof(randout) - outpos), outpos);
			data += outpos;
			size -= outpos;
		}

		*(int *)(randpool) = 0x69;
		*(int *)(randpool + sizeof(int)) = 0x69;

		// Recycle
		SHA1Init(&ctxt);
		SHA1Update(&ctxt, randpool, sizeof(randpool));
		SHA1Final(randout, &ctxt);
		
		SHA1Init(&ctxt);
		SHA1Update(&ctxt, (unsigned char *) &randcnt, sizeof(randcnt));
		SHA1Update(&ctxt, randpool, sizeof(randpool));
		SHA1Final(randpool, &ctxt);
		
		++randcnt;
		outpos = sizeof(randout);
	}

	if(size > 0)
	{
		memcpy(data, randout + (sizeof(randout) - outpos), size);
		outpos -= size;
	}

	return data;
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

	if(!sklen) 
		return NULL;

	while(key && !*sk)
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
		for(i = 0; i < klen; ++i)
			hbuf[i] = sk[i * 2];
	}

	SHA1Init(&ctxt);
	SHA1Update(&ctxt, hbuf, klen);
	SHA1Final(hout, &ctxt);

	for(i = 0; i < sizeof(hout); ++i)
		key[i * 2] = hout[i];

	if(klen)
	{
		for (i = 0; i < klen; ++i)
			hbuf[i] = sk[2 * i + 1];
	}

	SHA1Init(&ctxt);
	SHA1Update(&ctxt, hbuf, klen);
	SHA1Final(hout, &ctxt);

	for(i = 0; i < sizeof(hout); ++i)
		key[2 * i + 1] = hout[i];

	free(hbuf);
	return key;
}
