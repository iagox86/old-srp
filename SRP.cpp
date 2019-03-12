#include "bnSRP.h"

#define GETADDRESS(ord) GetProcAddress(hStorm, (LPCSTR)ord)
#define BSWAP(a,b,c,d) ((((((a << 8) | b) << 8) | c) << 8) | d)

/*BnSRP::BnSRP()
{
	exit(1);
}*/

BnSRP::BnSRP()
{
	InitVars();
}

BnSRP::~BnSRP()
{
	mStorm->BigDel(this->Modulus);
	mStorm->BigDel(this->Generator);
	mStorm->BigDel(this->PrivKey);
	mStorm->BigDel(this->PubKeyA);

	FreeLibrary(this->hStorm);
}

void BnSRP::InitVars()
{
	static const BYTE ModulusRaw[BIGINT_SIZE] = { 0x87, 0xc7, 0x23, 0x85, 0x65, 0xf6, 0x16, 0x12,
													0xd9, 0x12, 0x32, 0xc7, 0x78, 0x6c, 0x97, 0x7e,
													0x55, 0xb5, 0x92, 0xa0, 0x8c, 0xb6, 0x86, 0x21,
													0x03, 0x18, 0x99, 0x61, 0x8b, 0x1a, 0xff, 0xf8 };

	static const BYTE tempPrivKey[BIGINT_SIZE] = { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };

	static const unsigned int GeneratorRaw = 47;

	BYTE Buf1[SHA_DIGESTSIZE], Buf2[SHA_DIGESTSIZE];
//	BYTE Key[BIGINT_SIZE];
	SHA1_CTX ctx;

	// generate values
	mStorm->BigNew(&this->Modulus);
	mStorm->BigNew(&this->PrivKey);
	mStorm->BigNew(&this->PubKeyA);
	this->Generator = mStorm->BigIntegerFromInt(GeneratorRaw);
	this->Modulus = mStorm->BigIntegerFromBytes(ModulusRaw);
	//this->PrivKey = mStorm->BigIntegerFromBytes(GenKey(Key));
	this->PrivKey = mStorm->BigIntegerFromBytes(tempPrivKey);
	printf("The friggin' key is MADE!\n\n\n");

	SHA1Init(&ctx);
	SHA1Update(&ctx, ModulusRaw, BIGINT_SIZE);
	SHA1Final(Buf1, &ctx); // Buf1 = H(modulus)
	printf("Original Buf1: ");
	for (int i = 0; i < SHA_DIGESTSIZE; i++)
		printf("%02x ", Buf1[i]);
	printf("\n\n");

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)&GeneratorRaw, 1);
	SHA1Final(Buf2, &ctx); // Buf2 = H(generator)

	printf("Buf2: ");
	for (int i = 0; i < SHA_DIGESTSIZE; i++)
		printf("%02x ", Buf2[i]);
	printf("\n\n");

	printf("Buf1: ");
	for (int i = 0; i < SHA_DIGESTSIZE; ++i)
	{
		Buf1[i] ^= Buf2[i];	// buf1 = H(modulus) xor H(generator)
		printf("%02x ", Buf1[i]);
	}
	printf("\n\n");

	// hash: H(N) xor H(g)
	SHA1Init(&this->TotalCtx);
	SHA1Update(&this->TotalCtx, Buf1, SHA_DIGESTSIZE);

}

// returns a 32 byte result in buf
void BnSRP::MakeAuth(void *Buf)
{
	mStorm->BigPowMod(this->PubKeyA, this->Generator, this->PrivKey, this->Modulus);
	mStorm->BigIntegerToBytes(this->PubKeyA, Buf);

	printf("PubKeyA: ");
	for (int i = 0; i < 32; i++)
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

	x = mStorm->BigIntegerFromBytes(Hash, SHA_DIGESTSIZE);

	// compute v = g^x
	v = mStorm->BigIntegerFromInt(0);
	mStorm->BigPowMod(v, this->Generator, x, this->Modulus);

	// compute u
	BYTE KeyDataA[BIGINT_SIZE];
	mStorm->BigIntegerToBytes(this->PubKeyA, KeyDataA);

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)PubKeyB, BIGINT_SIZE);
	SHA1Final(Hash, &ctx);

	u = mStorm->BigIntegerFromInt(BSWAP(Hash[0], Hash[1], Hash[2], Hash[3]));

	// unblind g^b (mod N)
	gb = mStorm->BigIntegerFromBytes(PubKeyB);
	if (mStorm->BigCompare(gb, v) < 0)
		mStorm->BigAdd(gb, gb, this->Modulus);
	mStorm->BigSub(gb, gb, v);

	mStorm->BigDel(v);

	// compute gb^(a + ux) (mod N)
	BigBuffer e = mStorm->BigIntegerFromInt(0);
	mStorm->BigMul(e, x, u); // e = ux
	mStorm->BigAdd(e, e, this->PrivKey); // e = a + ux

	mStorm->BigDel(u);
	mStorm->BigDel(x);

	BigBuffer S = mStorm->BigIntegerFromInt(0);
	mStorm->BigPowMod(S, gb, e, this->Modulus); // gb^(a + ux)

	mStorm->BigDel(e);
	mStorm->BigDel(gb);

	// hash: (H(N) xor H(g)) | H(U) | s | A
	SHA1Update(&this->TotalCtx, KeyDataA, BIGINT_SIZE);
	// hash: (H(N) xor H(g)) | H(U) | s | A | B
	SHA1Update(&this->TotalCtx, (BYTE *)PubKeyB, BIGINT_SIZE);

	mStorm->BigIntegerToBytes(S, SessionData);
	::MakeSessionKey(this->SessionKey, SessionData, BIGINT_SIZE);
	mStorm->BigDel(S);

	// hash: (H(N) xor H(g)) | H(U) | s | A | B | K
	SHA1Update(&this->TotalCtx, this->SessionKey, sizeof(this->SessionKey));

	// put final hash in buffer
	SHA1Final((BYTE *)Buf, &this->TotalCtx);
}

BYTE *BnSRP::GenKey(BYTE *data)
{
	UINT outpos = 0, randcnt = 0, size = BIGINT_SIZE;
	BYTE randout[SHA_DIGESTSIZE], randpool[SHA_DIGESTSIZE];
	SHA1_CTX ctxt;

	memset(randout, 0, sizeof(randout));
	memset(randpool, 0, sizeof(randpool));

	srand((unsigned)time(NULL));

	while (size > outpos)
	{
		if (outpos > 0)
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
		SHA1Update(&ctxt, (unsigned char *)&randcnt, sizeof(randcnt));
		SHA1Update(&ctxt, randpool, sizeof(randpool));
		SHA1Final(randpool, &ctxt);

		++randcnt;
		outpos = sizeof(randout);
	}

	if (size > 0)
	{
		memcpy(data, randout + (sizeof(randout) - outpos), size);
		outpos -= size;
	}

	return data;
}

void BnSRP::GenerateSalt(void *Buf) {
	BYTE Buffer[BIGINT_SIZE];
	srand(time(NULL));
	for (int i = 0; i < 32; i++) {
		Buffer[i] = (rand() % 255);
	}
	memcpy(Buf, Buffer, BIGINT_SIZE);
}

/*
	Buf[SHA_DIGESTSIZE]
	Buf is the output of the account initial hash SHA1(USERNAME ":" PASSWORD)

	*User
	USERNAME

	*Pass
	PASSWORD
*/
void BnSRP::HashAccount(void *Buf, const char *User, const char *Pass) {
	char Username[32];
	char Password[32];
	SHA1_CTX ctx;

	strncpy_s(Username, User, sizeof(Username) - 1);
	strncpy_s(Password, Pass, sizeof(Password) - 1);
	_strupr_s(Username);
	_strupr_s(Password);

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)Username, (UINT)strlen(Username));
	SHA1Update(&ctx, (BYTE *)":", 1);
	SHA1Update(&ctx, (BYTE *)Password, (UINT)strlen(Password));
	SHA1Final((BYTE *)Buf, &ctx);
}

/*
	clienthash[SHA_DIGESTSIZE]
	to get X use HashAccount to get clienthash

	salt[BIGINT_SIZE]
	salt is given to you from the server
	salt is also created during create account
*/
void BnSRP::GetX(void *clienthash, void *salt) {
	SHA1_CTX ctx;
	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)salt, BIGINT_SIZE);
	SHA1Update(&ctx, (BYTE *)clienthash, SHA_DIGESTSIZE);
	SHA1Final((BYTE *)clienthash, &ctx);
}

void BnSRP::GenerateVerifyFromSalt(const char *User, const char *Pass, void *Salt, void *v) {
	BYTE Hash[SHA_DIGESTSIZE];
	BigBuffer x, verify;

	//TODO: throw error if !user or !pass or !Salt or !v

	//get x
	HashAccount(Hash, User, Pass);
	GetX(Hash, Salt);
	x = mStorm->BigIntegerFromBytes(Hash, SHA_DIGESTSIZE);

	//get v
	verify = mStorm->BigIntegerFromInt(0);
	mStorm->BigPowMod(verify, this->Generator, x, this->Modulus);

	//set v
	mStorm->BigIntegerToBytes(verify, (BYTE *)v, BIGINT_SIZE);

	printf("verifyer #1 (%s) --> ", User);
	displayArray((BYTE *)v, BIGINT_SIZE);

	mStorm->BigDel(x);
	mStorm->BigDel(verify);
}
/*
	*User, USERNAME
	*Pass, PASSWORD
	salt_out[BIGINT_SIZE], create account salt
	v_out[BIGINT_SIZE], create account v
*/
void BnSRP::MakeCreate(const char *User, const char *Pass, void *salt_out, void *v_out) {
	GenerateSalt(salt_out);
	GenerateVerifyFromSalt(User, Pass, salt_out, v_out);
}
