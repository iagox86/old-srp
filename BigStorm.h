#pragma once

#ifndef _BIGSTORM_H_
#define _BIGSTORM_H_

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

#include "Storm.h"


class BigStorm {
private:
	Storm *mStorm = Storm::Instance();
	BigBuffer m_value = NULL;
	std::string m_title = "BigStorm";

public:
	//Initalizers
	BigStorm();
	explicit BigStorm(const unsigned char *bytes, unsigned int lengthof);
	explicit BigStorm(const unsigned char *bytes, unsigned int lengthof, bool random);
	//explicit BigStorm(const BigStorm& modulus); //illegal
	explicit BigStorm(const UINT32 data);
	~BigStorm() throw ();

	//retrieve the buffer
	void RetrieveBytes(unsigned char *bufferout, unsigned int lengthrequest);

	//Title or Name of the value if you wish to keep track
	std::string class_name(void);
	void class_name(const std::string name);

	//Functionality
	BigStorm&	operator=	(const BigStorm& input);	   //iffy but it works as far as i can tell
	bool		operator==	(const UINT32& right)	const; //[good]
	bool		operator==	(const BigStorm& right) const; //[good]
	BigStorm	operator+	(const UINT32& right)	const; //[good]
	BigStorm	operator+	(const BigStorm& right) const; //[good]
	BigStorm	operator-	(const UINT32& right)	const; //[good]
	BigStorm	operator-	(const BigStorm& right) const; //[good]
	void		operator--	(void);
	void		operator++	(void);
	void		operator--	(int);
	void		operator++	(int);
	BigStorm	operator*	(const UINT32& right)	const; //[good]
	BigStorm	operator*	(const BigStorm& right) const; //[good]
	BigStorm	operator/	(const BigStorm& right) const; //[good]
	BigStorm	operator^	(const BigStorm& right) const; //[    ]
	BigStorm	operator%	(const BigStorm& right) const; //[    ]
	BigStorm	operator<<	(int bytesToShift)		const; //[slopy] but seems to work well
	BigStorm	operator>>	(int bytesToShift)		const; //[slopy] buggy as all fuck
	bool		operator>	(const UINT32& right)	const; //[good]
	bool		operator>	(const BigStorm& right) const; //[good]
	bool		operator<	(const UINT32& right)	const; //[good]
	bool		operator<	(const BigStorm& right) const; //[good]

	//PowMod
	BigStorm PowMod(const BigStorm& exponent, const BigStorm& modulus) const;

	//dump hex
	void DumpHex(void);

private:
	void frombytes(const unsigned char *bytesin, unsigned int lengthof);

};







#endif