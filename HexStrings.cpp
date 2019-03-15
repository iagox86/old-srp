#include <windows.h>
#include <string>
#include <stdexcept>
#include <algorithm>

#include "HexStrings.h"

void StringToHex(const UCHAR *datainput, UINT32 datalength, std::string &outbuffer)
{
	static const char *values = "0123456789ABCDEF";
	outbuffer = "";
	for (UINT i = 0; i < datalength; i++) {
		const UCHAR c = datainput[i];
		outbuffer += values[c >> 4];
		outbuffer += values[c & 15];
	}
}

void HexToString(const UCHAR *datainput, UINT32 datalength, UCHAR *OutPut)
{
	if (datalength & 1) throw std::invalid_argument("HexToString: Bad length!");
	static const char *values = "0123456789ABCDEF";

	for (UINT i = 0; i < datalength; i += 2)
	{
		char a = datainput[i];
		char b = datainput[i + 1];
		const char* c = std::lower_bound(values, values + 16, a);
		if (*c != a) throw std::invalid_argument("HexToString: [a] not a hex digit");
		const char* d = std::lower_bound(values, values + 16, b);
		if (*d != b) throw std::invalid_argument("HexToString: [b] not a hex digit");

		OutPut[i / 2] = ((c - values) << 4) | (d - values);
	}
}

void ReverseArray(const unsigned char *Ar1, unsigned int len, unsigned char *Ar2) {
	for (int i = 0; i < len; i++) {
		Ar2[i] = Ar1[(len - i) - 1];
	}
}