#pragma once

#ifndef _SRP3_H_
#define _SRP3_H_

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "t_sha.h"

#include <string>

#include "BigStorm.h"

#define SHA_DIGESTSIZE 20

class SRP3 {
private:
	Storm *mStorm = Storm::Instance();

public:
	SRP3(std::string username_, std::string password_, const unsigned char *salt_);
	SRP3(const char *username_, const char *password_, const unsigned char *salt_, const unsigned char *verify_);
	SRP3();
	~SRP3();

	void SetUsernameAndA(std::string username_, const unsigned char *A_);
	void SetUsernameAndA(const char *username_, const unsigned char *A_);
	//void SetUsernameAndA(const char *username_, const BigStorm& A_);

	void SetSalt(const unsigned char *salt_);
	void SetV(const unsigned char *v_);
	void Reset(bool reinit = false);
	void SetClientA(const unsigned char *A_);
	void SetClientA(const BigStorm& A_);
	void SetServerB(const unsigned char *B_);
	void SetServerB(const BigStorm& B_);

	BigStorm GetClientPrivateKey() const;
	BigStorm GetScrambler();

	/*
		secret out buffer must be 40 bytes long
	*/
	void hashsecret(BigStorm secret, unsigned char* secretoutbuffer);

	BigStorm GetVerifier() const;
	BigStorm GetSalt() const;

	BigStorm GetClientSessionPublicKey() const;
	BigStorm GetServerSessionPublicKey() const;

	/*
		must have B
	*/
	void GetHashedClientSecret(unsigned char *secretbufferout);
	/*
		must have A, v
	*/
	void GetHashedServerSecret(unsigned char *secretbufferout);

private:
	/*
		note you must have got B first
	*/
	BigStorm GetClientSecret();

	/*
		note you must have A, V first
	*/
	BigStorm GetServerSecret();

	/*
		must have A, B, K (40 char secret)
	*/
	BigStorm GetClientPasswordProof(const unsigned char *K_) const;

	/*
		must have A, M[1], K (40 char secret)
	*/
	BigStorm GetServerPasswordProof(BigStorm& M_, const unsigned char *K_) const;

private:
	int	init(const char* username_, const char* password_, const unsigned char *salt_, const unsigned char *verify_);

	//Init the Strings
	void InitUsername(const char *username_);
	void InitPassword(const char *password_);

	//Generate Salt
	void GenerateSalt(void *Buf);

	//init the starting vars
	void InitVars(void);
	
	//Initalize these
	BigStorm	N;	// modulus
	BigStorm	g;	// generator
	BigStorm	I;	// H(g) xor H(N) where H() is standard SHA1
	
	//
	BigStorm	PrivKey;	// session private key
	BigStorm	s;			// salt
	BigStorm	B;			// server public key
	BigStorm	A;			// Client public key
	BigStorm	v;			// verifier

	char	username[16];
	size_t	username_length;
	char	password[16];
	size_t	password_length;
	unsigned char raw_salt[32];
};


#endif