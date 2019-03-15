#include "Storm.h"

#pragma region "STORM.DLL"
Storm* Storm::sInstance = NULL;

Storm *Storm::Instance() {
	if (sInstance == NULL) {
		sInstance = new Storm();
	}
	return sInstance;
}

Storm::Storm() {
	InitStorm(StormLocation[0]);
}

Storm::~Storm() {
	FreeLibrary(hStorm);
}

void Storm::Release() {
	delete sInstance;
	sInstance = NULL;
}

bool Storm::InitStorm(char *storm) {
	if (!(this->hStorm = LoadLibrary(storm)))
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
	//BigMod = (SBigMod)GETADDRESS(621); //input issues (this can be cheated PowMod exponent value 1)
	//BigPow = (SBigPow)GETADDRESS(627); //input issues
	BigXor = (SBigXor)GETADDRESS(647);
	BigRand = (SBigRand)GETADDRESS(629);
	BigDiv = (SBigDiv)GETADDRESS(607);
	//BigShl = (SBigShl)GETADDRESS(633);
	//BigShr = (SBigShr)GETADDRESS(634);
	BigCopy = (SBigCopy)GETADDRESS(604); //..
	return true;
}

BigBuffer Storm::BigIntegerFromBytes(const void *Buf, DWORD Len)
{
	BigBuffer BigInt;

	BigNew(&BigInt);
	BigFromBinary(BigInt, Buf, Len);

	return BigInt;
}

void Storm::BigIntegerToBytes(BigBuffer BigInt, void *Buf, DWORD Len)
{
	DWORD lengthout = 0;
	BigToBinaryBuffer(BigInt, Buf, Len, &lengthout);
	lengthout;
}

BigBuffer Storm::BigIntegerFromInt(DWORD num)
{
	BigBuffer BigInt;

	BigNew(&BigInt);
	BigFromUnsigned(BigInt, num);

	return BigInt;
}
#pragma endregion
