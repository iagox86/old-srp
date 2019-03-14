#include "BigStorm.h"

#include <stdexcept>
#include <cassert>

/*
	opening the BigStorm initalizes with a value of 0
*/
BigStorm::BigStorm() {
	m_value = mStorm->BigIntegerFromInt(0);
}

BigStorm::BigStorm(const unsigned char *bytes, unsigned int lengthof) {
	if (!bytes) {
		throw std::invalid_argument("BigStorm: no bytes provided.");
		return;
	}
	frombytes(bytes, lengthof);
}

BigStorm::BigStorm(const UINT32 data) {
	this->m_value = mStorm->BigIntegerFromInt(data);
}

BigStorm::~BigStorm() throw() {
	m_title = "";
	if(this->m_value)
		mStorm->BigDel(this->m_value);
}

void BigStorm::frombytes(const unsigned char *bytesin, unsigned int lengthof) {
	m_value = mStorm->BigIntegerFromBytes(bytesin, lengthof);
}

std::string BigStorm::class_name(void) {
	return m_title;
}

void BigStorm::class_name(const std::string name) {
	m_title = name;
}

void BigStorm::RetrieveBytes(unsigned char *bufferout, unsigned int lengthrequest) {
	if (!bufferout) {
		throw std::invalid_argument("BigStorm: NULL Buffer.");
		return;
	}
	if (lengthrequest == 0) {
		throw std::invalid_argument("BigStorm: 0 length requested.");
		return;
	}
	mStorm->BigIntegerToBytes(m_value, bufferout, lengthrequest);
}

BigStorm& BigStorm::operator=(const BigStorm& input)
{
	if (&input != this) {
		mStorm->BigDel(this->m_value);

		this->m_title = input.m_title;
		
		BYTE RAW_BYTES[BIGINT_SIZE];
		memset(RAW_BYTES, 0, BIGINT_SIZE);
		mStorm->BigIntegerToBytes(input.m_value, RAW_BYTES, BIGINT_SIZE);
		this->m_value = mStorm->BigIntegerFromBytes(RAW_BYTES, BIGINT_SIZE);

		return *this;
	}
	return *this;
}

BigStorm BigStorm::operator+(const BigStorm& right) const
{
	BigStorm out;
	mStorm->BigAdd(out.m_value, this->m_value, right.m_value);
	return out;
}

BigStorm BigStorm::operator+(const UINT32& right) const
{
	BigStorm r(right);
	BigStorm out;
	mStorm->BigAdd(out.m_value, this->m_value, r.m_value);
	return out;
}

BigStorm BigStorm::operator-(const UINT32& right) const
{
	BigStorm r(right);
	BigStorm out;
	mStorm->BigSub(out.m_value, this->m_value, r.m_value);
	return out;

}

BigStorm BigStorm::operator-(const BigStorm& right) const
{
	BigStorm out;
	mStorm->BigSub(out.m_value, this->m_value, right.m_value);
	return out;
}

BigStorm BigStorm::operator^(const BigStorm& right) const
{
	BigStorm out;
	mStorm->BigXor(out.m_value, this->m_value, right.m_value);
	return out;
}

void BigStorm::operator-- (void) {
	if (*this == 0) { return; };
	BigStorm out(1);
	mStorm->BigSub(this->m_value, this->m_value, out.m_value);
	return;
}

void BigStorm::operator++ (void) {
	BigStorm out(1);
	mStorm->BigAdd(this->m_value, this->m_value, out.m_value);
	return;
}

void BigStorm::operator-- (int) {
	BigStorm out(1);
	if (*this < out) { 
		if (*this == 0) { return; }
		mStorm->BigSub(this->m_value, this->m_value, this->m_value);
		return; 
	};
	mStorm->BigSub(this->m_value, this->m_value, out.m_value);
	return;
}

void BigStorm::operator++ (int) {
	BigStorm out(1);
	mStorm->BigAdd(this->m_value, this->m_value, out.m_value);
	return;
}

/* slow and steady? */
BigStorm BigStorm::operator%(const BigStorm& right) const
{
	BigStorm out;

	if (right == 0) { return out; } //should throw an error you cant mod by 0
	if (right == 1) { return out; } //mod 1 == 0
	if (*this == right) { return out; } //same value % same value == 0

	if (*this > right)
	{
		mStorm->BigSub(out.m_value, this->m_value, right.m_value);
		while (out > right) {
			mStorm->BigSub(out.m_value, out.m_value, right.m_value);
		}
	}

	if (out == right) { //same value % same value == 0
		mStorm->BigSub(out.m_value, out.m_value, out.m_value);
	}
	return out;
}

BigStorm BigStorm::operator*(const UINT32& right) const
{
	BigStorm out(right);
	mStorm->BigMul(out.m_value, this->m_value, out.m_value);
	return out;
}

BigStorm BigStorm::operator*(const BigStorm& right) const
{
	BigStorm out;
	mStorm->BigMul(out.m_value, this->m_value, right.m_value);
	return out;
}

BigStorm BigStorm::operator/(const BigStorm& right) const
{
	BigStorm out;
	mStorm->BigDiv(out.m_value, this->m_value, right.m_value);
	return out;
}

/* shitty shift lol but works now */
BigStorm BigStorm::operator<<(int bytesToShift) const
{
	UINT32 shiftvalue = (1 << (bytesToShift));
	BigStorm out(shiftvalue);
	mStorm->BigMul(out.m_value, this->m_value, out.m_value);
	return out;
}

/* this is slightly fucked if you use it to much on the same BigInt */
BigStorm BigStorm::operator>>(int bytesToShift) const
{
	UINT32 shiftvalue = (1 << (bytesToShift));
	BigStorm out(shiftvalue);
	mStorm->BigDiv(out.m_value, this->m_value, out.m_value);
	return out;
}

bool BigStorm::operator==(const BigStorm& right) const
{
	if (&right != this) {
		int result = mStorm->BigCompare(this->m_value, right.m_value);
		if (result == 0) {
			return true;
		}
		return false;
	}
	return true;
}

bool BigStorm::operator==(const UINT32& right) const
{
	BigStorm r(right);
	r.DumpHex();
	if (&r != this) {
		int result = mStorm->BigCompare(this->m_value, r.m_value);
		if (result == 0) {
			return true;
		}
		return false;
	}
	return true;
}

bool BigStorm::operator>(const UINT32& right) const
{
	BigStorm r(right);
	int result = mStorm->BigCompare(this->m_value, r.m_value);
	if (result == 1) {
		return true;
	}
	return false;
}

bool BigStorm::operator<(const UINT32& right) const
{
	BigStorm r(right);
	int result = mStorm->BigCompare(this->m_value, r.m_value);
	if (result == -1) {
		return true;
	}
	return false;
}

bool BigStorm::operator>(const BigStorm& right) const
{
	if (&right != this) {
		int result = mStorm->BigCompare(this->m_value, right.m_value);
		if (result == 1) {
			return true;
		}
		return false;
	}
	return false;
}

bool BigStorm::operator<(const BigStorm& right) const
{
	if (&right != this) {
		int result = mStorm->BigCompare(this->m_value, right.m_value);
		if (result == -1) {
			return true;
		}
		return false;
	}
	return false;
}

void BigStorm::DumpHex(void) {
	BYTE RAW_BYTES[BIGINT_SIZE];
	memset(RAW_BYTES, 0, BIGINT_SIZE);
	mStorm->BigIntegerToBytes(this->m_value, RAW_BYTES, BIGINT_SIZE);

	static const char *values = "0123456789ABCDEF";
	std::string outbuffer = "";
	for (UINT i = 0; i < BIGINT_SIZE; i++) {
		const UCHAR c = RAW_BYTES[i];
		outbuffer += values[c >> 4];
		outbuffer += values[c & 15];
	}

	printf_s("%s: %s\n", this->m_title.c_str(), outbuffer.c_str());
}