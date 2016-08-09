/*

Author: Jason Williams <jdw@cromulence.com>

Copyright (c) 2015 Cromulence LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/
#ifndef __VM_H__
#define __VM_H__

#include <cutil_list.h>

#include "dma.h"
#include "mmu.h"
#include "cpu.h"

class cgc_CCLF;

class cgc_CVM
{
public:
	cgc_CVM( void *secret_page );
	~cgc_CVM( );

	bool cgc_Init( cgc_CCLF *pFile );

	bool cgc_Run( void );

private:
	cgc_CMMU	m_oMMU;
	cgc_CCPU	m_oCPU;
	cgc_CDMA 	m_oDMA;

	void *m_pMagicPage;

	CUtil::DLL_LIST( cgc_CPeripheral, m_peripheralListLink ) m_oPeripheralList;
};

#endif // __VM_H__