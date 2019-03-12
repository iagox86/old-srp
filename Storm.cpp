#include "StormSRP.h"

#include <stdlib.h>
#include <time.h>
#include <stdio.h>


#define BSWAP(a,b,c,d) ((((((a << 8) | b) << 8) | c) << 8) | d)

#pragma region "Unrelated to the actual Storm Class"
unsigned char *MakeSessionKeyX(unsigned char *dest,
	unsigned char*data,
	unsigned int length);

void displayArrayX(BYTE *array, int length)
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
unsigned char *MakeSessionKeyX(unsigned char *key,
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


#pragma region "BSRP"

BSRP::BSRP(const char *username, const char *password) {
	set_username_c(username, password);
	InitVars();
}

BSRP::BSRP() {
	InitVars();
}

BSRP::~BSRP() {
	mStorm->BigDel(this->Modulus);
	mStorm->BigDel(this->Generator);
	mStorm->BigDel(this->PrivKey);
	mStorm->BigDel(this->PubKeyA);
}

BYTE *BSRP::GenKey(BYTE *data)
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

void BSRP::InitVars()
{
	BYTE Buf1[SHA_DIGESTSIZE], Buf2[SHA_DIGESTSIZE];
	BYTE Key[BIGINT_SIZE];
	SHA1_CTX ctx;

	// generate values
	mStorm->BigNew(&this->Modulus);
	mStorm->BigNew(&this->PrivKey);
	mStorm->BigNew(&this->PubKeyA);
	this->Generator = mStorm->BigIntegerFromInt(GeneratorRaw);
	this->Modulus = mStorm->BigIntegerFromBytes(ModulusRaw);
	this->PrivKey = mStorm->BigIntegerFromBytes(GenKey(Key));
	//this->PrivKey = mStorm->BigIntegerFromBytes(tempPrivKey);
//	printf("The friggin' key is MADE!\n\n\n");

	SHA1Init(&ctx);
	SHA1Update(&ctx, ModulusRaw, BIGINT_SIZE);
	SHA1Final(Buf1, &ctx); // Buf1 = H(modulus)
//	printf("Original Buf1: ");
//	for (int i = 0; i < SHA_DIGESTSIZE; i++)
//		printf("%02x ", Buf1[i]);
//	printf("\n\n");

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)&GeneratorRaw, 1);
	SHA1Final(Buf2, &ctx); // Buf2 = H(generator)

//	printf("Buf2: ");
//	for (int i = 0; i < SHA_DIGESTSIZE; i++)
//		printf("%02x ", Buf2[i]);
//	printf("\n\n");

//	printf("Buf1: ");
	for (int i = 0; i < SHA_DIGESTSIZE; ++i)
	{
		Buf1[i] ^= Buf2[i];	// buf1 = H(modulus) xor H(generator)
//		printf("%02x ", Buf1[i]);
	}
//	printf("\n\n");

	// hash: H(N) xor H(g)
	SHA1Init(&this->TotalCtx);
	SHA1Update(&this->TotalCtx, Buf1, SHA_DIGESTSIZE);

}

void BSRP::set_verify(void *v) {
	memcpy(Verifier, v, BIGINT_SIZE);
}

void BSRP::set_salt(void *salt) {
	memcpy(Salt, salt, BIGINT_SIZE);
}

void BSRP::set_b(void *b) {
	memcpy(ServerKeyB, b, BIGINT_SIZE);
}

void BSRP::set_username_s(const char *username, void *salt, void *v, void *A) {
	strncpy_s(USERNAME, username, sizeof(USERNAME) - 1);
	_strupr_s(USERNAME);
	memcpy(Salt, salt, BIGINT_SIZE);
	memcpy(Verifier, v, BIGINT_SIZE);
	memcpy(ClientKeyA, A, BIGINT_SIZE);
}

void BSRP::set_username_c(const char *username, const char *password) {
	strncpy_s(USERNAME, username, sizeof(USERNAME) - 1);
	strncpy_s(PASSWORD, password, sizeof(PASSWORD) - 1);
	_strupr_s(USERNAME);
	_strupr_s(PASSWORD);
}

void BSRP::GenerateSalt(void *Buf) {
	BYTE Buffer[BIGINT_SIZE];
	srand(time(NULL));
	for (int i = 0; i < 32; i++) {
		Buffer[i] = (rand() % 254) + 1;
	}
	memcpy(Buf, Buffer, BIGINT_SIZE);
}

/*
	Server Public Session Key
*/
void BSRP::GetB(void *Buf) {
	//TODO: check if !buf, !v
	//B = new BigInt((v + g.powm(b, N)) % N);
	BigBuffer b, V, tmpg;
	V = mStorm->BigIntegerFromBytes(this->Verifier, BIGINT_SIZE);
	b = mStorm->BigIntegerFromBytes(this->PubKeyA, BIGINT_SIZE);
	
	mStorm->BigNew(&tmpg);

	mStorm->BigPowMod(tmpg, this->Generator, b, this->Modulus);
	mStorm->BigAdd(V, V, tmpg);
	//mStorm->BigMod(V, V, this->Modulus);

	mStorm->BigIntegerToBytes(V, Buf);

	mStorm->BigDel(b);
	mStorm->BigDel(V);
	mStorm->BigDel(tmpg);
}

void BSRP::get_u(void *Buf, void *b) {
	BYTE Hash[SHA_DIGESTSIZE];
	SHA1_CTX ctx;
	BYTE u[4];

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)b, BIGINT_SIZE);
	SHA1Final((BYTE *)Hash, &ctx);

	u[0] = Hash[3];
	u[1] = Hash[2];
	u[2] = Hash[1];
	u[3] = Hash[0];

	memcpy(Buf, u, 4);
}

void BSRP::get_c_x(void *Buf) {
	SHA1_CTX ctx;

	HashAccount(Buf);

	SHA1Init(&ctx);
	SHA1Update(&ctx, Salt, BIGINT_SIZE);
	SHA1Update(&ctx, (BYTE *)Buf, SHA_DIGESTSIZE);
	SHA1Final((BYTE *)Buf, &ctx);
}

void BSRP::get_c_v(void *Buf) {
	BigBuffer x;
	BYTE Hash[SHA_DIGESTSIZE];

	get_c_x(Hash);
	// v = g^x % N
	//g.modPow(get_x(salt), N);

	x = mStorm->BigIntegerFromBytes(Hash, SHA_DIGESTSIZE);
	mStorm->BigPowMod(x, this->Generator, x, this->Modulus);
	mStorm->BigIntegerToBytes(x, Buf);

	mStorm->BigDel(x);
}

void BSRP::get_c_s(void *Buf) {
// S = (B - v)^(a + ux) % N
//
//BigIntegerEx S_base = N.add(new BigIntegerEx(BigIntegerEx.LITTLE_ENDIAN, B)).subtract(get_v(s)).mod(N);
//BigIntegerEx S_exp = a.add(get_u(B).multiply(get_x(s)));
//return S_base.modPow(S_exp, N).toByteArray();
//
	BYTE V[BIGINT_SIZE];
	BigBuffer bn, v;
	get_c_v(V);

	v = mStorm->BigIntegerFromBytes(V);

	//mStorm->BigNew(bn);
	bn = mStorm->BigIntegerFromBytes(this->Modulus);

	mStorm->BigAdd(bn, bn, ServerKeyB);
	mStorm->BigSub(bn, bn, v);
	mStorm->BigMod(bn, bn, this->Modulus);

	mStorm->BigIntegerToBytes(bn, Buf);

	mStorm->BigDel(bn); 
	//mStorm->BigDel(V);
}

void BSRP::get_m1(void *Buf) {
	SHA1_CTX ctx;
	BYTE Hash[SHA_DIGESTSIZE]; //BIGINT_SIZE
	BYTE cs[BIGINT_SIZE];
	BYTE K[SHA_DIGESTSIZE * 2];

	//Username Hash
	HashUsername(Hash);

	//Get S
	get_c_s(cs);
	mStorm->BigIntegerFromBytes(cs, BIGINT_SIZE);

	//Get K
	GetClientK(K, cs);

	SHA1Init(&ctx);
	SHA1Update(&ctx, Raw_I, SHA_DIGESTSIZE);
	SHA1Update(&ctx, Hash, SHA_DIGESTSIZE);
	SHA1Update(&ctx, Salt, BIGINT_SIZE);
	SHA1Update(&ctx, ClientKeyA, BIGINT_SIZE);
	SHA1Update(&ctx, ServerKeyB, BIGINT_SIZE);
	SHA1Update(&ctx, K, (SHA_DIGESTSIZE * 2)); //GetK
	SHA1Final((BYTE *)Buf, &ctx);
}

/*
	Buf[SHA_DIGESTSIZE]
	Buf is the output of the account initial hash SHA1(USERNAME ":" PASSWORD)
*/
void BSRP::HashAccount(void *Buf) {
	SHA1_CTX ctx;

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)USERNAME, (UINT)strlen(USERNAME));
	SHA1Update(&ctx, (BYTE *)":", 1);
	SHA1Update(&ctx, (BYTE *)PASSWORD, (UINT)strlen(PASSWORD));
	SHA1Final((BYTE *)Buf, &ctx);
}

/*
	Buf[SHA_DIGESTSIZE]
	Buf is the output of the account initial hash SHA1(USERNAME)
*/
void BSRP::HashUsername(void *Buf) {
	SHA1_CTX ctx;

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)USERNAME, (UINT)strlen(USERNAME));
	SHA1Final((BYTE *)Buf, &ctx);
}

/*
	clienthash[SHA_DIGESTSIZE]
	to get X use HashAccount to get clienthash

	salt[BIGINT_SIZE]
	salt is given to you from the server
	salt is also created during create account
*/
void BSRP::GetX(void *clienthash, void *salt) {
	SHA1_CTX ctx;
	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)salt, BIGINT_SIZE);
	SHA1Update(&ctx, (BYTE *)clienthash, SHA_DIGESTSIZE);
	SHA1Final((BYTE *)clienthash, &ctx);
}

void BSRP::GenerateVerifyFromSalt(void *Salt, void *v) {
	BYTE Hash[SHA_DIGESTSIZE];
	BigBuffer x, verify;

	//TODO: throw error if !user or !pass or !Salt or !v

	//get x
	HashAccount(Hash);
	GetX(Hash, Salt);
	x = mStorm->BigIntegerFromBytes(Hash, SHA_DIGESTSIZE);

	//get v
	verify = mStorm->BigIntegerFromInt(0);
	mStorm->BigPowMod(verify, this->Generator, x, this->Modulus);

	//set v
	mStorm->BigIntegerToBytes(verify, (BYTE *)v, BIGINT_SIZE);

//	printf("verifyer #1 (%s) --> ", User);
//	displayArray((BYTE *)v, BIGINT_SIZE);

	mStorm->BigDel(x);
	mStorm->BigDel(verify);
}

//Get Client S
void BSRP::GetClientSecret(void *Buf, void *s, void *b, void *a, void *v) {
	//BYTE Scrambler[SHA_DIGESTSIZE];
	BYTE Hash[SHA_DIGESTSIZE];
	BYTE _u[4];
	BigBuffer A, B, U, V, S, X, tmp;
	
	//(N + B - g.powm(x, N)).powm((x*u) + a, N)

	get_u(_u, b);
	//GetScrambler(Scrambler, b);
	HashAccount(Hash);
	GetX(Hash, s);
	X = mStorm->BigIntegerFromBytes(Hash, SHA_DIGESTSIZE);

	B = mStorm->BigIntegerFromBytes(b, BIGINT_SIZE);
	A = mStorm->BigIntegerFromBytes(a, BIGINT_SIZE);
	V = mStorm->BigIntegerFromBytes(v, BIGINT_SIZE);
	U = mStorm->BigIntegerFromBytes(_u);
	S = mStorm->BigIntegerFromInt(0);
	tmp = mStorm->BigIntegerFromInt(0);

	mStorm->BigAdd(B, this->Modulus, B); // [N + B]
	mStorm->BigPowMod(tmp, this->Generator, X, this->Modulus); // [g.powm(x, N)]
	mStorm->BigSub(B, B, X); // [(N + B - g.powm(x, N))]

	mStorm->BigMul(X, X, U); // [(x*u)]
	mStorm->BigAdd(X, X, A); // [(x*u) + a]

	mStorm->BigPowMod(S, B, X, this->Modulus); // [(N + B - g.powm(x, N)).powm((x*u) + a, N)]

	mStorm->BigIntegerToBytes(S, (BYTE *)Buf, BIGINT_SIZE);

	mStorm->BigDel(A); mStorm->BigDel(B); mStorm->BigDel(U); mStorm->BigDel(V); mStorm->BigDel(S); mStorm->BigDel(X); mStorm->BigDel(tmp);
}

//Get Server S
void BSRP::GetServerSecret(void *Buf, void *a, void *v) {
	BYTE PubKeyB[BIGINT_SIZE];
	//BYTE Scrambler[SHA_DIGESTSIZE];
	BYTE _u[4];

	GetB(PubKeyB);
	//GetScrambler(Scrambler, PubKeyB);
	get_u(_u, PubKeyB);

	//((A * v.powm(u, N)) % N).powm(b, N);
	BigBuffer A, B, U, V, S;
	A = mStorm->BigIntegerFromBytes(a, BIGINT_SIZE);
	B = mStorm->BigIntegerFromBytes(PubKeyB, BIGINT_SIZE);
	U = mStorm->BigIntegerFromBytes(_u);
	V = mStorm->BigIntegerFromBytes(v, BIGINT_SIZE);
	S = mStorm->BigIntegerFromInt(0);

	mStorm->BigPowMod(V, V, U, this->Modulus);
	mStorm->BigMul(A, A, V);
	mStorm->BigMod(A, A, this->Modulus);
	mStorm->BigPowMod(S, A, B, this->Modulus);

	mStorm->BigIntegerToBytes(S, (BYTE *)Buf, BIGINT_SIZE);

	mStorm->BigDel(A); mStorm->BigDel(B); mStorm->BigDel(U); mStorm->BigDel(V); mStorm->BigDel(S);
}

//Servers K
void BSRP::GetServerK(void *Buf, void *a, void *v) {
	SHA1_CTX ctx;
	BYTE K[40];
	BYTE oddbuf1[16];
	BYTE evnbuf2[16];
	BYTE ServerS[BIGINT_SIZE];

	GetServerSecret(ServerS, a, v);

	for (int i = 0; i < 16; i++) {
		oddbuf1[i] = ServerS[i * 2];
		evnbuf2[i] = ServerS[(i * 2) + 1];
	}
	BYTE oddHash1[SHA_DIGESTSIZE];
	BYTE evnHash2[SHA_DIGESTSIZE];

	SHA1Init(&ctx);
	SHA1Update(&ctx, oddbuf1, 16);
	SHA1Final(oddHash1, &ctx);

	SHA1Init(&ctx);
	SHA1Update(&ctx, evnbuf2, 16);
	SHA1Final(evnHash2, &ctx);

	for (int i = 0; i < SHA_DIGESTSIZE; i++) {
		K[i * 2] = oddHash1[i];
		K[(i * 2) + 1] = evnHash2[i];
	}

	memcpy(Buf, K, 40);
}

//Client K
void BSRP::GetClientK(void *Buf, void *S) {
	SHA1_CTX ctx;
	BYTE K[40];
	BYTE oddbuf1[16];
	BYTE evnbuf2[16];
	BYTE ClientS[BIGINT_SIZE];

	memcpy(ClientS, S, BIGINT_SIZE);

	for (int i = 0; i < 16; i++) {
		oddbuf1[i] = ClientS[i * 2];
		evnbuf2[i] = ClientS[(i * 2) + 1];
	}
	BYTE oddHash1[SHA_DIGESTSIZE];
	BYTE evnHash2[SHA_DIGESTSIZE];

	SHA1Init(&ctx);
	SHA1Update(&ctx, oddbuf1, 16);
	SHA1Final(oddHash1, &ctx);

	SHA1Init(&ctx);
	SHA1Update(&ctx, evnbuf2, 16);
	SHA1Final(evnHash2, &ctx);

	for (int i = 0; i < SHA_DIGESTSIZE; i++) {
		K[i * 2] = oddHash1[i];
		K[(i * 2) + 1] = evnHash2[i];
	}

	memcpy(Buf, K, 40);
}

void BSRP::GetClientPasswordProof(void *Buf, const char *User, void *a, void *b, void *s, void *k) {
	char Username[32];
	BYTE USERHASH[SHA_DIGESTSIZE];
	SHA1_CTX ctx;

	strncpy_s(Username, User, sizeof(Username) - 1);
	_strupr_s(Username);

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)Username, (UINT)strlen(Username));
	SHA1Final(USERHASH, &ctx);

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)Raw_I, SHA_DIGESTSIZE);
	SHA1Update(&ctx, USERHASH, SHA_DIGESTSIZE);
	SHA1Update(&ctx, (BYTE *)s, BIGINT_SIZE);
	SHA1Update(&ctx, (BYTE *)a, BIGINT_SIZE);
	SHA1Update(&ctx, (BYTE *)b, BIGINT_SIZE);
	SHA1Update(&ctx, (BYTE *)k, (SHA_DIGESTSIZE * 2));
	SHA1Final((BYTE *)Buf, &ctx);
}

void BSRP::GetServerPasswordProof(void *Buf, void *a, void *m, void *k) {
	SHA1_CTX ctx;

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)a, BIGINT_SIZE);
	SHA1Update(&ctx, (BYTE *)m, SHA_DIGESTSIZE);
	SHA1Update(&ctx, (BYTE *)k, (SHA_DIGESTSIZE * 2));
	SHA1Final((BYTE *)Buf, &ctx);
}

//S
void BSRP::MakeServerProof(void *Buf, void *a, void *v) {
	BYTE PubKeyB[BIGINT_SIZE];
	SHA1_CTX ctx;
	BYTE Hash[SHA_DIGESTSIZE];
	BigBuffer A, B, V, U;

	//get a
	A = mStorm->BigIntegerFromBytes(a, BIGINT_SIZE); 
	//get v
	V = mStorm->BigIntegerFromBytes(v, BIGINT_SIZE); 
	//get b
	GetB(PubKeyB);
	B = mStorm->BigIntegerFromBytes(PubKeyB, BIGINT_SIZE);

	// compute u
	BYTE KeyDataA[BIGINT_SIZE];
	mStorm->BigIntegerToBytes(this->PubKeyA, KeyDataA);

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)PubKeyB, BIGINT_SIZE);
	SHA1Final(Hash, &ctx);

	U = mStorm->BigIntegerFromInt(BSWAP(Hash[0], Hash[1], Hash[2], Hash[3]));

	BigBuffer S = mStorm->BigIntegerFromInt(0);
	//math time.
	mStorm->BigPowMod(V, V, U, this->Modulus);
	mStorm->BigMul(A, A, V);
	mStorm->BigPowMod(S, A, B, this->Modulus);
	//A is server S

}

// returns a 32 byte result in buf
void BSRP::MakeAuth(void *Buf)
{
	mStorm->BigPowMod(this->PubKeyA, this->Generator, this->PrivKey, this->Modulus);
	mStorm->BigIntegerToBytes(this->PubKeyA, Buf);

	//printf("PubKeyA: ");
	//for (int i = 0; i < 32; i++)
	//	printf("%02x ", ((BYTE*)Buf)[i]);
	//printf("\n");
}

// returns a 20 byte hash
void BSRP::MakeProof(void *Buf, const char *User, const char *Pass, void *Salt, void *PubKeyB)
{
	char Username[32];
	char Password[32];
	BYTE Hash[SHA_DIGESTSIZE];
	BYTE SessionData[BIGINT_SIZE];
	SHA1_CTX ctx;

	BigBuffer x, v, u, gb;

	strncpy_s(Username, User, sizeof(Username) - 1);
	strncpy_s(Password, Pass, sizeof(Password) - 1);
	_strupr_s(Username);
	_strupr_s(Password);

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)Username, (UINT)strlen(Username));
	SHA1Final(Hash, &ctx);

	// Checkpoint number 1
	//printf("PROOF #1 (%s) --> ", Username);
	//displayArray(Hash, SHA_DIGESTSIZE);



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
	::MakeSessionKeyX(this->SessionKey, SessionData, BIGINT_SIZE);
	mStorm->BigDel(S);

	// hash: (H(N) xor H(g)) | H(U) | s | A | B | K
	SHA1Update(&this->TotalCtx, this->SessionKey, sizeof(this->SessionKey));

	// put final hash in buffer
	SHA1Final((BYTE *)Buf, &this->TotalCtx);
}

/*
	*User, USERNAME
	*Pass, PASSWORD
	salt_out[BIGINT_SIZE], create account salt
	v_out[BIGINT_SIZE], create account v
*/
void BSRP::MakeCreate(void *salt_out, void *v_out) {
	GenerateSalt(salt_out);
	GenerateVerifyFromSalt(salt_out, v_out);
}

#pragma endregion

