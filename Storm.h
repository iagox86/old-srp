#ifndef _STORM_H_
#define _STORM_H_

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define BIGINT_SIZE 32
#define GETADDRESS(ord) GetProcAddress(hStorm, (LPCSTR)ord)


/*  Currently useing 1.0.9.0 storm.dll */
#define StormLocation "./storm.dll"
typedef void * BigBuffer;

class Storm {
private:
	static Storm* sInstance;

	Storm();
	~Storm();

	bool InitStorm(char *storm);

public:
	static Storm *Instance();
	static void Release();

	typedef void(__stdcall * SBigNew)(BigBuffer *buf); // 624
	typedef void(__stdcall * SBigDel)(BigBuffer ptr); // 606
	typedef void(__stdcall * SBigPowMod)(BigBuffer result, BigBuffer base, BigBuffer expnt, BigBuffer mod); // 628
	typedef void(__stdcall * SBigFromUnsigned)(BigBuffer result, DWORD num); // 612
	typedef void(__stdcall * SBigFromBinary)(BigBuffer result, const void *in, int count); // 609
	typedef void(__stdcall * SBigToBinaryBuffer)(BigBuffer in, void *result, DWORD incount, DWORD *outcount); // 638
	typedef void(__stdcall * SBigAdd)(BigBuffer result, BigBuffer a, BigBuffer b); // 601
	typedef void(__stdcall * SBigSub)(BigBuffer result, BigBuffer a, BigBuffer b); // 636
	typedef void(__stdcall * SBigMul)(BigBuffer result, BigBuffer a, BigBuffer b); // 622
	typedef int(__stdcall *SBigCompare)(BigBuffer a, BigBuffer b); // 603
	//Additions
	typedef void(__stdcall * SBigMod)(BigBuffer result, BigBuffer a, BigBuffer b); // 621
	typedef void(__stdcall * SBigPow)(BigBuffer result, BigBuffer a, BigBuffer b); // 627
	typedef void(__stdcall * SBigXor)(BigBuffer result, BigBuffer a, BigBuffer b); // 647


	SBigNew BigNew;
	SBigDel BigDel;
	SBigPowMod BigPowMod;
	SBigFromUnsigned BigFromUnsigned;
	SBigFromBinary BigFromBinary;
	SBigToBinaryBuffer BigToBinaryBuffer;
	SBigAdd BigAdd;
	SBigSub BigSub;
	SBigMod BigMod;
	SBigMul BigMul;
	SBigPow BigPow;
	SBigXor BigXor;
	SBigCompare BigCompare;

	void BigIntegerToBytes(BigBuffer BigInt, void *Buf, DWORD Len = BIGINT_SIZE);
	BigBuffer BigIntegerFromBytes(const void *Buf, DWORD Len = BIGINT_SIZE);
	BigBuffer BigIntegerFromInt(DWORD num);

private:
	HMODULE hStorm;
};

#endif
