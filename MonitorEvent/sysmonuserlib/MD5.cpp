/************************************************************
MD5У��ͼ������C��
************************************************************/

//DEFINES for MD5

#define UINT4 unsigned int


/* F, G, H and I are basic MD5 functions. */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits. */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation. */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
    }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
    }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
    }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
    }

// Constants for MD5 Transform routine.
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

//===============

#include <stdio.h>
#include <string.h>
#include "Md5.h"

//Endian convert: big <-> little
unsigned int conv(unsigned int a)
{
	unsigned int b = 0;
	b |= (a << 24) & 0xff000000;
	b |= (a << 8) & 0x00ff0000;
	b |= (a >> 8) & 0x0000ff00;
	b |= (a >> 24) & 0x000000ff;
	return b;
}

//MD5ժҪ
MD5VAL md5(char * str, unsigned int size)
{
	if (size == 0)
		size = strlen(str);
	unsigned int m = size % 64;
	unsigned int lm = size - m;  //�������鳤��
	unsigned int ln;  //���ݲ�λ�󳤶�
	if (m<56)
		ln = lm + 64;
	else
		ln = lm + 128;
	char * strw = new char[ln];
	unsigned int i;
	//����ԭ�ִ���������strw
	for (i = 0; i<size; i++)
		strw[i] = str[i];
	//��λ
	strw[i++] = 0x80;
	for (i; i<ln - 8; i++)
		strw[i] = 0x00;
	//������
	unsigned int * x = (unsigned int *)(strw + i);
	*(x++) = size << 3;
	*(x++) = size >> 29;
	//��ʼ��MD5����
	MD5VAL val = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
	unsigned int &a = val.a, &b = val.b, &c = val.c, &d = val.d;
	unsigned int aa, bb, cc, dd;
	for (i = 0; i<ln; i += 64)
	{
		x = (unsigned int *)(strw + i);
		// Save the values
		aa = a; bb = b; cc = c; dd = d;
		// Round 1
		FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
		FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
		FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
		FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
		FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
		FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
		FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
		FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
		FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
		FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
		FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
		FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
		FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
		FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
		FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
		FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */
		// Round 2
		GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
		GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
		GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
		GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
		GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
		GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
		GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
		GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
		GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
		GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
		GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
		GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
		GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
		GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
		GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
		GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */
		// Round 3
		HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
		HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
		HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
		HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
		HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
		HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
		HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
		HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
		HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
		HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
		HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
		HH(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
		HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
		HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
		HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
		HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */
		// Round 4 */
		II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
		II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
		II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
		II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
		II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
		II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
		II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
		II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
		II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
		II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
		II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
		II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
		II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
		II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
		II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
		II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */
		// Add the original values
		a += aa;
		b += bb;
		c += cc;
		d += dd;
	}
	delete[] strw;
	return val;
}

#define BUFFER_SIZE 4096   //������64�ı���

//MD5�ļ�ժҪ
MD5VAL md5File(FILE * fpin)
{
	MD5VAL val = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

	char* pBuffer = nullptr;
	pBuffer = new char[BUFFER_SIZE + 64];
	if (pBuffer == nullptr || (!pBuffer))
		return val;
	memset(pBuffer, 0, BUFFER_SIZE + 64);

	unsigned int &a = val.a, &b = val.b, &c = val.c, &d = val.d;
	unsigned int aa, bb, cc, dd;
	unsigned int i, j, count, co;
	unsigned int * x;
	i = 0;
	do
	{
		count = fread(pBuffer, 1, BUFFER_SIZE, fpin);
		i += count;
		if (count == BUFFER_SIZE)
			co = BUFFER_SIZE;
		else
		{
			j = count;
			pBuffer[j++] = 0x80;
			for (j; j % 64 != 56; j++)
				pBuffer[j] = 0x00;
			*(unsigned int *)(pBuffer + j) = i << 3; j += 4;
			*(unsigned int *)(pBuffer + j) = i >> 29; j += 4;
			co = j;
		}
		for (j = 0; j<co; j += 64)
		{
			x = (unsigned int *)(pBuffer + j);
			// Save the values
			aa = a; bb = b; cc = c; dd = d;
			// Round 1
			FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
			FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
			FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
			FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
			FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
			FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
			FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
			FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
			FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
			FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
			FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
			FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
			FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
			FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
			FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
			FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */
			// Round 2
			GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
			GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
			GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
			GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
			GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
			GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
			GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
			GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
			GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
			GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
			GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
			GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
			GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
			GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
			GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
			GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */
			// Round 3
			HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
			HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
			HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
			HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
			HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
			HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
			HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
			HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
			HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
			HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
			HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
			HH(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
			HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
			HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
			HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
			HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */
			// Round 4 */
			II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
			II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
			II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
			II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
			II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
			II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
			II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
			II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
			II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
			II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
			II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
			II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
			II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
			II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
			II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
			II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */
			// Add the original values
			a += aa;
			b += bb;
			c += cc;
			d += dd;
		}
	} while (count == BUFFER_SIZE);

	if (pBuffer) {
		delete[] pBuffer;
		pBuffer = nullptr;
	}
	return val;
}

/* ����ļ���MD5ֵ */
char * md5FileValue(char * fname)
{
	try
	{
		char cMd5[1204] = { 0, };
		MD5VAL val;
		FILE* fp = fopen(fname, "rb");
		if (fp)
		{
			val = md5File(fp);
			sprintf(cMd5, "%08x%08x%08x%08x", conv(val.a), conv(val.b), conv(val.c), conv(val.d));
			fclose(fp);
		}
		return cMd5;
	}
	catch (...)
	{
		return nullptr;
	}
}

/* ����ִ���MD5ֵ */
void md5Str(char * input, char * output)
{
	try
	{
		MD5VAL val;
		val = md5(input, strlen(input));
		sprintf(output, "%08x%08x%08x%08x", conv(val.a), conv(val.b), conv(val.c), conv(val.d));
	}
	catch (...)
	{
	}
}