#ifndef _STORM_H_
#define _STORM_H_

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define BIGINT_SIZE 32
#define GETADDRESS(ord) GetProcAddress(hStorm, (LPCSTR)ord)


/*  Currently useing 1.0.9.0 storm.dll */
static char StormLocation[2][20] = { "./Storm12606401.dll", "./Storm1075535.dll" };

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

	/* assuming bad inputs */
	//typedef int(__stdcall * SBigMod)(BigBuffer result, BigBuffer a, BigBuffer b); // 621 (base returns something just dont know what) (result returns a, a returns a, b returns b)
	//typedef void(__stdcall * SBigPow)(BigBuffer result, BigBuffer a, BigBuffer b); // 627

	/*
		SBigXor
			Equivilant to:
				Return2[i] = A_bytes[i] ^ B_btyes[i]

		return values
			8 Good call
			1 when a and b were both initialized with int 0
	*/
	typedef int(__stdcall * SBigXor)(BigBuffer result, BigBuffer a, BigBuffer b); // 647

	/* 
		Dosent realy seem like a Rand at all, 
			result1 Output can fill a BigBuffer.
			constantvalue, dosent change after the call
			result2 Seems like a UINT64 output. (when using a full BigBuffer on  as the constantvalue)
	*/
	typedef void(__stdcall * SBigRand)(BigBuffer result1, BigBuffer constantvalue, BigBuffer result2); // 629
	

	SBigNew BigNew;
	SBigDel BigDel;
	SBigPowMod BigPowMod;
	SBigFromUnsigned BigFromUnsigned;
	SBigFromBinary BigFromBinary;
	SBigToBinaryBuffer BigToBinaryBuffer;
	SBigAdd BigAdd;
	SBigSub BigSub;
	//SBigMod BigMod; //asuming wrong input types.
	SBigMul BigMul;
	//SBigPow BigPow; //asuming wrong input types.
	SBigXor BigXor;
	SBigCompare BigCompare;
	SBigRand BigRand;
	void BigIntegerToBytes(BigBuffer BigInt, void *Buf, DWORD Len = BIGINT_SIZE);
	BigBuffer BigIntegerFromBytes(const void *Buf, DWORD Len = BIGINT_SIZE);
	BigBuffer BigIntegerFromInt(DWORD num);

private:
	HMODULE hStorm;
};

#endif
