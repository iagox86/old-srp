#include "SRP3.h"
#include "HexStrings.h"

#include <cstdio>
#include <stdexcept>
#include <cassert>
#include <cctype>
#include <chrono>



UINT8 GeneratorRaw = 0x2FU;
const BYTE ModulusRaw[] = { 0x87, 0xc7, 0x23, 0x85, 0x65, 0xf6, 0x16, 0x12, 0xd9, 0x12, 0x32, 0xc7, 0x78, 0x6c, 0x97, 0x7e, 0x55, 0xb5, 0x92, 0xa0, 0x8c, 0xb6, 0x86, 0x21, 0x03, 0x18, 0x99, 0x61, 0x8b, 0x1a, 0xff, 0xf8 };
//const BYTE ModulusRaw[] = { 0xF8, 0xFF, 0x1A, 0x8B, 0x61, 0x99, 0x18, 0x03, 0x21, 0x86, 0xB6, 0x8C, 0xA0, 0x92, 0xB5, 0x55, 0x7E, 0x97, 0x6C, 0x78, 0xC7, 0x32, 0x12, 0xD9, 0x12, 0x16, 0xF6, 0x65, 0x85, 0x23, 0xC7, 0x87 };
const BYTE NLS_I[] = { 0x6c, 0xe, 0x97, 0xed, 0xa, 0xf9, 0x6b, 0xab, 0xb1, 0x58, 0x89, 0xeb, 0x8b, 0xba, 0x25, 0xa4, 0xf0, 0x8c, 0x1, 0xf8 };
//const BYTE NLS_I[] = { 0xF8, 0x01, 0x8C, 0xF0, 0xA4, 0x25, 0xBA, 0x8B, 0xEB, 0x89, 0x58, 0xB1, 0xAB, 0x6B, 0xF9, 0x0A, 0xED, 0x97, 0x0E, 0x6C };

SRP3::SRP3(std::string username_, std::string password_, const unsigned char *salt_) {
	InitVars();
	if (username_ == "") {
		throw std::invalid_argument("SRP3: got NULL username_");
		return;
	}
	if (password_ == "") { // should throw this also, server init has been changed
		if (!salt_) {
			throw std::invalid_argument("SRP3: got NULL password with NULL salt");
			return;
		}
		init(username_.c_str(), NULL, salt_, NULL);
		return;
	}
	init(username_.c_str(), password_.c_str(), salt_, NULL);
}

SRP3::SRP3(const char *username_, const char *password_, const unsigned char *salt_, const unsigned char *verify_) {
	InitVars();
	if (!username_) {
		throw std::invalid_argument("SRP3: got NULL username_");
		return;
	}
	if (!password_) {
		if (!salt_ || !verify_) {
			throw std::invalid_argument("SRP3: got NULL password with NULL salt or NULL verify");
			return;
		}
		init(username_, NULL, salt_, verify_); // Server init
		return;
	}
	init(username_, password_, salt_, verify_); // Client init
}

SRP3::SRP3() {
	InitVars();
}

SRP3::~SRP3() {
	Reset();
}

void SRP3::Reset(bool reinit) {
	ZeroMemory(username, 16);
	username_length = 0;
	ZeroMemory(password, 16);
	password_length = 0;

	/*if (this->N != NULL) { mStorm->BigDel(this->N); }
	if (this->g != NULL) { mStorm->BigDel(this->g); }
	if (this->I != NULL) { mStorm->BigDel(this->I); }
	if (this->PrivKey != NULL) { mStorm->BigDel(this->PrivKey); }
	if (this->s != NULL) { mStorm->BigDel(this->s); }
	if (this->B != NULL) { mStorm->BigDel(this->B); }
	if (this->A != NULL) { mStorm->BigDel(this->A); }*/

	if (reinit) {
		InitVars();
	}
}

void SRP3::InitVars(void) {
	ZeroMemory(username, 16);
	username_length = 0;
	ZeroMemory(password, 16);
	password_length = 0;

	// our constant values
	this->g = BigStorm(GeneratorRaw);
	this->N = BigStorm(ModulusRaw, BIGINT_SIZE);
	this->N.DumpHex();

	//const unsigned char *bytes, unsigned int lengthof, bool random

	this->PrivKey = BigStorm(ModulusRaw, BIGINT_SIZE, true);
	this->I = BigStorm(NLS_I, SHA_DIGESTSIZE);
}

void SRP3::InitUsername(const char *username_) {
	username_length = std::strlen(username_);
	strncpy_s(username, username_, username_length);
	_strupr_s(username);
}

void SRP3::InitPassword(const char *password_) {
	password_length = std::strlen(password_);
	strncpy_s(password, password_, password_length);
	_strupr_s(password);
}

void SRP3::GenerateSalt(void *Buf) {
	BYTE Buffer[BIGINT_SIZE];
	srand(time(NULL));
	for (int i = 0; i < 32; i++) {
		Buffer[i] = (rand() % 254) + 1;
	}
	memcpy(Buf, Buffer, BIGINT_SIZE);
}

void SRP3::SetSalt(const unsigned char *salt_) {
	if (!salt_) {
		throw std::invalid_argument("SRP3: got NULL salt [s]");
		return;
	}

	memcpy(raw_salt, salt_, BIGINT_SIZE);

	s = BigStorm(raw_salt, BIGINT_SIZE);
}

/*
	servers set verify
*/
void SRP3::SetV(const unsigned char *v_) {
	if (!v_) {
		throw std::invalid_argument("SRP3: got NULL v");
		return;
	}
	v = BigStorm(v_, BIGINT_SIZE);
}

/* 
	Clients set verify.
*/
void SRP3::SetV() {
	this->v = GetVerifier(); // to get a salt and verify to test against [http://harpywar.pvpgn.pl/?do=srp]
	//this->v.class_name("Client Manual v");
	//this->v.DumpHex();
}

int	SRP3::init(const char* username_, const char* password_, const unsigned char *salt_, const unsigned char *verify_) {
	if (!username) {
		throw std::invalid_argument("SRP3: got NULL username_");
		return -1;
	}
	InitUsername(username_);

	if (!((password_ == NULL) ^ (salt_ == NULL))) {
		throw std::invalid_argument("SRP3: need to init with EITHER password_ OR salt_");
		return -1;
	}

	if (password_ != NULL) {
		InitPassword(password_);

		//a = COMMON::LARGEMATH::BigInt::random(32) % N; //a = [BigBuffer PrivKey]
		GenerateSalt(raw_salt);
		s = BigStorm(raw_salt, BIGINT_SIZE);
	}
	else {
		password_length = 0;
		//b = COMMON::LARGEMATH::BigInt::random(32) % N; //b = [BigBuffer PrivKey]
		SetSalt(salt_);
		SetV(verify_);
	}

	return 1;
}

void SRP3::SetClientA(const unsigned char *A_) {
	if (!A_) {
		throw std::invalid_argument("SRP3: got NULL A");
		return;
	}

	A = BigStorm(A_, BIGINT_SIZE);
	A.DumpHex();
}

void SRP3::SetClientA(const BigStorm& A_) {
	A = A_;
	A.DumpHex();
}

void SRP3::SetServerB(const unsigned char *B_) {
	if (!B_) {
		throw std::invalid_argument("SRP3: got NULL B");
		return;
	}

	B = BigStorm(B_, BIGINT_SIZE);
}

void SRP3::SetServerB(const BigStorm& B_) {
	B = B_;
	B.DumpHex();
}

void SRP3::SetUsernameAndA(std::string username_, const unsigned char *A_) {
	if (username_ == "") {
		throw std::invalid_argument("SRP3: got NULL username_");
		return;
	}
	InitUsername(username_.c_str());
	SetClientA(A_);
}

void SRP3::SetUsernameAndA(const char *username_, const unsigned char *A_) {
	if (!username_) {
		throw std::invalid_argument("SRP3: got NULL username_");
		return;
	}
	InitUsername(username_);
	SetClientA(A_);
}

BigStorm SRP3::GetClientPrivateKey() const {
	unsigned char userhash[SHA_DIGESTSIZE];
	SHA1_CTX ctx;

	SHA1Init(&ctx);
	SHA1Update(&ctx, (unsigned char *)username, username_length);
	SHA1Update(&ctx, (unsigned char *)":", 1);
	SHA1Update(&ctx, (unsigned char *)password, password_length);
	SHA1Final((unsigned char *)userhash, &ctx);

	SHA1Init(&ctx);
	SHA1Update(&ctx, (unsigned char *)raw_salt, BIGINT_SIZE);
	SHA1Update(&ctx, (unsigned char *)userhash, SHA_DIGESTSIZE);
	SHA1Final((unsigned char *)userhash, &ctx);

	return BigStorm(userhash, SHA_DIGESTSIZE);
}

BigStorm SRP3::GetServerSessionPublicKey() const {
	if (B == 0)
	{
		return ((v + g.PowMod(this->PrivKey, this->N)) % this->N);
	}
	return B;
}

BigStorm SRP3::GetScrambler() {
	unsigned char raw_B[BIGINT_SIZE];
	unsigned char hash[SHA_DIGESTSIZE];
	UINT32 scrambler = 0;
	SHA1_CTX ctx;

	B.RetrieveBytes(raw_B, BIGINT_SIZE);

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)raw_B, BIGINT_SIZE);
	SHA1Final((BYTE *)hash, &ctx);

	scrambler = *(UINT32*)hash; //not swapping either way k should still ==

	return BigStorm(scrambler);
}

BigStorm SRP3::GetClientSecret() {
	BigStorm x = GetClientPrivateKey();
	BigStorm u = GetScrambler();
	return (N + B - g.PowMod(x, N)).PowMod((x * u) + PrivKey, N);
}

BigStorm SRP3::GetServerSecret() {
	BigStorm B = GetServerSessionPublicKey();
	BigStorm u = GetScrambler();

	/*B.DumpHex();
	A.DumpHex();
	u.DumpHex();
	v.DumpHex();
	PrivKey.DumpHex();
	N.DumpHex();*/

	return ((A * v.PowMod(u, N)) % N).PowMod(PrivKey, N);
}

void SRP3::hashsecret(const BigStorm& secret, unsigned char* secretoutbuffer) {
	int i;
	unsigned char raw_secret[BIGINT_SIZE];
	unsigned char odd[16], even[16]; memset(odd, 0, 16); memset(even, 0, 16);
	unsigned char odd_hash[SHA_DIGESTSIZE], even_hash[SHA_DIGESTSIZE]; memset(odd_hash, 0, SHA_DIGESTSIZE); memset(even_hash, 0, SHA_DIGESTSIZE);
	SHA1_CTX ctx;

	BigStorm s_ = secret;
	s_.RetrieveBytes(raw_secret, BIGINT_SIZE);

	std::string outhex = "";
	StringToHex(raw_secret, BIGINT_SIZE, outhex);
	printf_s("rs1: %s\n", outhex.c_str());

	unsigned char* Sp = raw_secret;
	unsigned char* op = odd;
	unsigned char* ep = even;

	for (i = 0; i < 16; i++) {
		*(op++) = *(Sp++);
		*(ep++) = *(Sp++);
	}

	outhex = "";
	StringToHex(odd, 16, outhex);
	printf_s("odd1: %s\n", outhex.c_str());
	outhex = "";
	StringToHex(even, 16, outhex);
	printf_s("even1: %s\n", outhex.c_str());

	SHA1Init(&ctx);
	SHA1Update(&ctx, (unsigned char *)odd, 16);
	SHA1Final((unsigned char *)odd_hash, &ctx);

	SHA1Init(&ctx);
	SHA1Update(&ctx, (unsigned char *)even, 16);
	SHA1Final((unsigned char *)even_hash, &ctx);

	outhex = "";
	StringToHex(even_hash, 20, outhex);
	printf_s("even-h1: %s\n", outhex.c_str());
	outhex = "";
	StringToHex(odd_hash, 20, outhex);
	printf_s("odd-h1: %s\n", outhex.c_str());


	Sp = secretoutbuffer; //point to the out buffer now
	op = odd_hash;
	ep = even_hash;

	for (i = 0; i < 20; i++) {
		*(Sp++) = *(op++);
		*(Sp++) = *(ep++);
	}
}

/*
	Tested and found working.
*/
BigStorm SRP3::GetVerifier() const {
	BigStorm pk_, n_, g_;
	pk_ = GetClientPrivateKey(); n_ = this->N;

	pk_.DumpHex();
	n_.DumpHex();

	return this->g.PowMod(pk_, n_);
}

BigStorm SRP3::GetSalt() const {
	return s;
}

BigStorm SRP3::GetClientSessionPublicKey() const {
	BigStorm pk_, n_;
	pk_ = this->PrivKey; n_ = this->N;

	pk_.DumpHex();
	n_.DumpHex();

	return this->g.PowMod(pk_, n_);
}

void SRP3::GetHashedClientSecret(unsigned char *secretbufferout) {
	BigStorm clientsecret = GetClientSecret();
	clientsecret.DumpHex();
	hashsecret(clientsecret, secretbufferout);
}

void SRP3::GetHashedServerSecret(unsigned char *secretbufferout) {
	BigStorm serversecret = GetServerSecret();
	serversecret.DumpHex();
	hashsecret(serversecret, secretbufferout);
}

BigStorm SRP3::GetClientPasswordProof(const unsigned char *K_) const {
	unsigned char proofdata[176];
	unsigned char userhash[SHA_DIGESTSIZE];
	unsigned char proofhash[SHA_DIGESTSIZE];
	//temp values..
	BigStorm I_, s_, A_, B_;
	SHA1_CTX ctx;

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)username, username_length);
	SHA1Final((BYTE *)userhash, &ctx);

	I_ = I; s_ = s; A_ = A; B_ = B;
	I_.RetrieveBytes(proofdata + 0, SHA_DIGESTSIZE);
	memcpy(proofdata + 20, userhash, SHA_DIGESTSIZE);
	s_.RetrieveBytes(proofdata + 40, BIGINT_SIZE);
	A_.RetrieveBytes(proofdata + 72, BIGINT_SIZE);
	B_.RetrieveBytes(proofdata + 104, BIGINT_SIZE);
	memcpy(proofdata + 136, K_, 40);

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)proofdata, 176);
	SHA1Final((BYTE *)proofhash, &ctx);

	return BigStorm(proofhash, SHA_DIGESTSIZE);
}

BigStorm SRP3::GetServerPasswordProof(BigStorm& M_, const unsigned char *K_) const {
	unsigned char proofdata[92];
	unsigned char proofhash[SHA_DIGESTSIZE];
	SHA1_CTX ctx;
	BigStorm A_ = A;

	A_.RetrieveBytes(proofdata + 0, BIGINT_SIZE);
	M_.RetrieveBytes(proofdata + 32, SHA_DIGESTSIZE);
	memcpy(proofdata + 52, K_, 40);

	SHA1Init(&ctx);
	SHA1Update(&ctx, (BYTE *)proofdata, 92);
	SHA1Final((BYTE *)proofhash, &ctx);

	return BigStorm(proofhash, SHA_DIGESTSIZE);
}

