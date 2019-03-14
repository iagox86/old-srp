#pragma once

void StringToHex(const UCHAR *datainput, UINT32 datalength, std::string &outbuffer);
void HexToString(const UCHAR *datainput, UINT32 datalength, UCHAR *OutPut);
void ReverseArray(const char *Ar1, unsigned int len, unsigned char *Ar2);