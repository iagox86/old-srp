#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "t_sha.h"

#define BIGINT_SIZE 32
#define SHA_DIGESTSIZE 20

typedef void * BigBuffer;

class BnSRP
{
public:
	BnSRP();
	BnSRP(char *Storm);
	virtual ~BnSRP();

	bool InitStorm(const char *Storm);
	void MakeAuth(void *Buf);
	void MakeProof(void *Buf,
				   const char *User,
				   const char *Pass,
				   void *Salt,
				   void *PubKey);

protected:
	typedef void (__stdcall * SBigNew)(BigBuffer *buf); // 624
	typedef void (__stdcall * SBigDel)(BigBuffer ptr); // 606
	typedef void (__stdcall * SBigPowMod)(BigBuffer result, BigBuffer base, BigBuffer expnt, BigBuffer mod); // 628
	typedef void (__stdcall * SBigFromUnsigned)(BigBuffer result, DWORD num); // 612
	typedef void (__stdcall * SBigFromBinary)(BigBuffer result, const void *in, int count); // 609
	typedef void (__stdcall * SBigToBinaryBuffer)(BigBuffer in, void *result, DWORD incount, DWORD *outcount); // 638
	typedef void (__stdcall * SBigAdd)(BigBuffer result, BigBuffer a, BigBuffer b); // 601
	typedef void (__stdcall * SBigSub)(BigBuffer result, BigBuffer a, BigBuffer b); // 636
	typedef void (__stdcall * SBigMul)(BigBuffer result, BigBuffer a, BigBuffer b); // 622
	typedef int (__stdcall *SBigCompare)(BigBuffer a, BigBuffer b); // 603
	
	SBigNew BigNew;
	SBigDel BigDel;
	SBigPowMod BigPowMod;
	SBigFromUnsigned BigFromUnsigned;
	SBigFromBinary BigFromBinary;
	SBigToBinaryBuffer BigToBinaryBuffer;
	SBigAdd BigAdd;
	SBigSub BigSub;
	SBigMul BigMul;
	SBigCompare BigCompare;

	void BigIntegerToBytes(BigBuffer BigInt, void *Buf, DWORD Len = BIGINT_SIZE);
	BigBuffer BigIntegerFromBytes(const void *Buf, DWORD Len = BIGINT_SIZE);
	BigBuffer BigIntegerFromInt(DWORD num);

private:
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