/* aria.c
**
** Copyright (C) 2016 Doug Currie, Londonderry, NH, USA
** 
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files (the "Software"), to deal
** in the Software without restriction, including without limitation the rights
** to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
** copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions:
** 
** The above copyright notice and this permission notice shall be included in
** all copies or substantial portions of the Software.
** 
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
*/

/* This file implements the ARIA Encryption Algorithm as per IETF RFC-5794 
*/

#include <stdint.h>

#ifdef ARIA_TEST
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "timer_e.h"
#include "xorshift_e.h"
#define WHEN_ARIA_TEST(x) x
#else
#define WHEN_ARIA_TEST(x)
#endif

/* From: RFC-5794 A Description of the ARIA Encryption Algorithm
** 
** 2.  Algorithm Description
** 
**    The algorithm consists of a key scheduling part and data randomizing
**    part.
** 
** 2.1.  Notations
** 
**    The following notations are used in this document to describe the
**    algorithm.
** 
**       ^   bitwise XOR operation
**       <<< left circular rotation
**       >>> right circular rotation
**       ||  concatenation of bit strings
**       0x  hexadecimal representation
** 
*/

typedef struct aria_u128_s { uint64_t left; uint64_t right; } aria_u128_t;

static inline aria_u128_t rol (aria_u128_t x, uint8_t cnt) /* 0 < cnt < 64 */
{
  aria_u128_t y;
  y.left  = (x.left  << cnt) | (x.right >> (64 - cnt));
  y.right = (x.right << cnt) | (x.left  >> (64 - cnt));
  return y;
}

static inline aria_u128_t ror (aria_u128_t x, uint8_t cnt) /* 0 < cnt < 64 */
{
  aria_u128_t y;
  y.right = (x.right >> cnt) | (x.left  << (64 - cnt));
  y.left  = (x.left  >> cnt) | (x.right << (64 - cnt));
  return y;
}

static inline aria_u128_t xor (aria_u128_t x, aria_u128_t y)
{
  aria_u128_t z;
  z.left  = x.left  ^ y.left;
  z.right = x.right ^ y.right;
  return z;
}

#ifdef ARIA_TEST
static void print_aria_u128 (aria_u128_t x)
{
  fprintf(stderr, "{ 0x%016"PRIx64", 0x%016"PRIx64" }", x.left, x.right);
}
#endif

/*
** 2.4.2.  Substitution Layers
** 
**    ARIA has two types of substitution layers that alternate between
**    rounds.  Type 1 is used in the odd rounds, and type 2 is used in the
**    even rounds.
** 
**    Type 1 substitution layer SL1 is an algorithm that takes a 16-byte
**    string x0 || x1 ||...|| x15 as input and outputs a 16-byte string
**    y0 || y1 ||...|| y15 as follows.
** 
**    y0 = SB1(x0),  y1 = SB2(x1),  y2 = SB3(x2),  y3 = SB4(x3),
**    y4 = SB1(x4),  y5 = SB2(x5),  y6 = SB3(x6),  y7 = SB4(x7),
**    y8 = SB1(x8),  y9 = SB2(x9),  y10= SB3(x10), y11= SB4(x11),
**    y12= SB1(x12), y13= SB2(x13), y14= SB3(x14), y15= SB4(x15).
** 
**    Type 2 substitution layer SL2 is an algorithm that takes a 16-byte
**    string x0 || x1 ||...|| x15 as input and outputs a 16-byte string
**    y0 || y1 ||...|| y15 as follows.
** 
**    y0 = SB3(x0),  y1 = SB4(x1),  y2 = SB1(x2),  y3 = SB2(x3),
**    y4 = SB3(x4),  y5 = SB4(x5),  y6 = SB1(x6),  y7 = SB2(x7),
**    y8 = SB3(x8),  y9 = SB4(x9),  y10= SB1(x10), y11= SB2(x11),
**    y12= SB3(x12), y13= SB4(x13), y14= SB1(x14), y15= SB2(x15).
** 
**    Here, SB1, SB2, SB3, and SB4 are S-boxes that take an 8-bit string as
**    input and output an 8-bit string.  These S-boxes are defined by the
**    following look-up tables.
** 
**       SB1:
**           0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
**        00 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
**        10 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
**        20 b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
**        30 04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
**        40 09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
**        50 53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
**        60 d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
**        70 51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
**        80 cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
**        90 60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
**        a0 e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
**        b0 e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
**        c0 ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
**        d0 70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
**        e0 e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
**        f0 8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
** 
**       SB2:
**           0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
**        00 e2 4e 54 fc 94 c2 4a cc 62 0d 6a 46 3c 4d 8b d1
**        10 5e fa 64 cb b4 97 be 2b bc 77 2e 03 d3 19 59 c1
**        20 1d 06 41 6b 55 f0 99 69 ea 9c 18 ae 63 df e7 bb
**        30 00 73 66 fb 96 4c 85 e4 3a 09 45 aa 0f ee 10 eb
**        40 2d 7f f4 29 ac cf ad 91 8d 78 c8 95 f9 2f ce cd
**        50 08 7a 88 38 5c 83 2a 28 47 db b8 c7 93 a4 12 53
**        60 ff 87 0e 31 36 21 58 48 01 8e 37 74 32 ca e9 b1
**        70 b7 ab 0c d7 c4 56 42 26 07 98 60 d9 b6 b9 11 40
**        80 ec 20 8c bd a0 c9 84 04 49 23 f1 4f 50 1f 13 dc
**        90 d8 c0 9e 57 e3 c3 7b 65 3b 02 8f 3e e8 25 92 e5
**        a0 15 dd fd 17 a9 bf d4 9a 7e c5 39 67 fe 76 9d 43
**        b0 a7 e1 d0 f5 68 f2 1b 34 70 05 a3 8a d5 79 86 a8
**        c0 30 c6 51 4b 1e a6 27 f6 35 d2 6e 24 16 82 5f da
**        d0 e6 75 a2 ef 2c b2 1c 9f 5d 6f 80 0a 72 44 9b 6c
**        e0 90 0b 5b 33 7d 5a 52 f3 61 a1 f7 b0 d6 3f 7c 6d
**        f0 ed 14 e0 a5 3d 22 b3 f8 89 de 71 1a af ba b5 81
** 
**       SB3:
**           0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
**        00 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb
**        10 7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb
**        20 54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e
**        30 08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25
**        40 72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92
**        50 6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84
**        60 90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06
**        70 d0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b
**        80 3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73
**        90 96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e
**        a0 47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b
**        b0 fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4
**        c0 1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f
**        d0 60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef
**        e0 a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61
**        f0 17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d
** 
**       SB4:
**           0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
**        00 30 68 99 1b 87 b9 21 78 50 39 db e1 72  9 62 3c
**        10 3e 7e 5e 8e f1 a0 cc a3 2a 1d fb b6 d6 20 c4 8d
**        20 81 65 f5 89 cb 9d 77 c6 57 43 56 17 d4 40 1a 4d
**        30 c0 63 6c e3 b7 c8 64 6a 53 aa 38 98 0c f4 9b ed
**        40 7f 22 76 af dd 3a 0b 58 67 88 06 c3 35 0d 01 8b
**        50 8c c2 e6 5f 02 24 75 93 66 1e e5 e2 54 d8 10 ce
**        60 7a e8 08 2c 12 97 32 ab b4 27 0a 23 df ef ca d9
**        70 b8 fa dc 31 6b d1 ad 19 49 bd 51 96 ee e4 a8 41
**        80 da ff cd 55 86 36 be 61 52 f8 bb 0e 82 48 69 9a
**        90 e0 47 9e 5c 04 4b 34 15 79 26 a7 de 29 ae 92 d7
**        a0 84 e9 d2 ba 5d f3 c5 b0 bf a4 3b 71 44 46 2b fc
**        b0 eb 6f d5 f6 14 fe 7c 70 5a 7d fd 2f 18 83 16 a5
**        c0 91 1f 05 95 74 a9 c1 5b 4a 85 6d 13 07 4f 4e 45
**        d0 b2 0f c9 1c a6 bc ec 73 90 7b cf 59 8f a1 f9 2d
**        e0 f2 b1 00 94 37 9f d0 2e 9c 6e 28 3f 80 f0 3d d3
**        f0 25 8a b5 e7 42 b3 c7 ea f7 4c 11 33 03 a2 ac 60
** 
**    For example, SB1(0x23) = 0x26 and SB4(0xef) = 0xd3.  Note that SB3
**    and SB4 are the inverse functions of SB1 and SB2, respectively, and
**    accordingly SL2 is the inverse of SL1.
*/

static const uint8_t SB1[] = 
{
  /*        0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
  /* 00 */  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
  /* 10 */, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
  /* 20 */, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15
  /* 30 */, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
  /* 40 */, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84
  /* 50 */, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf
  /* 60 */, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8
  /* 70 */, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2
  /* 80 */, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73
  /* 90 */, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb
  /* a0 */, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79
  /* b0 */, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08
  /* c0 */, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a
  /* d0 */, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e
  /* e0 */, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf
  /* f0 */, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
static const uint8_t SB2[] = 
{
  /*        0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
  /* 00 */  0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1
  /* 10 */, 0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1
  /* 20 */, 0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb
  /* 30 */, 0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb
  /* 40 */, 0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd
  /* 50 */, 0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53
  /* 60 */, 0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1
  /* 70 */, 0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40
  /* 80 */, 0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc
  /* 90 */, 0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5
  /* a0 */, 0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43
  /* b0 */, 0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8
  /* c0 */, 0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda
  /* d0 */, 0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c
  /* e0 */, 0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d
  /* f0 */, 0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81
};
static const uint8_t SB3[] = 
{
  /*        0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
  /* 00 */  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
  /* 10 */, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
  /* 20 */, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e
  /* 30 */, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
  /* 40 */, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
  /* 50 */, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84
  /* 60 */, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06
  /* 70 */, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b
  /* 80 */, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73
  /* 90 */, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
  /* a0 */, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b
  /* b0 */, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4
  /* c0 */, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f
  /* d0 */, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef
  /* e0 */, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
  /* f0 */, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
static const uint8_t SB4[] = 
{
  /*        0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
  /* 00 */  0x30, 0x68, 0x99, 0x1b, 0x87, 0xb9, 0x21, 0x78, 0x50, 0x39, 0xdb, 0xe1, 0x72, 0x09, 0x62, 0x3c
  /* 10 */, 0x3e, 0x7e, 0x5e, 0x8e, 0xf1, 0xa0, 0xcc, 0xa3, 0x2a, 0x1d, 0xfb, 0xb6, 0xd6, 0x20, 0xc4, 0x8d
  /* 20 */, 0x81, 0x65, 0xf5, 0x89, 0xcb, 0x9d, 0x77, 0xc6, 0x57, 0x43, 0x56, 0x17, 0xd4, 0x40, 0x1a, 0x4d
  /* 30 */, 0xc0, 0x63, 0x6c, 0xe3, 0xb7, 0xc8, 0x64, 0x6a, 0x53, 0xaa, 0x38, 0x98, 0x0c, 0xf4, 0x9b, 0xed
  /* 40 */, 0x7f, 0x22, 0x76, 0xaf, 0xdd, 0x3a, 0x0b, 0x58, 0x67, 0x88, 0x06, 0xc3, 0x35, 0x0d, 0x01, 0x8b
  /* 50 */, 0x8c, 0xc2, 0xe6, 0x5f, 0x02, 0x24, 0x75, 0x93, 0x66, 0x1e, 0xe5, 0xe2, 0x54, 0xd8, 0x10, 0xce
  /* 60 */, 0x7a, 0xe8, 0x08, 0x2c, 0x12, 0x97, 0x32, 0xab, 0xb4, 0x27, 0x0a, 0x23, 0xdf, 0xef, 0xca, 0xd9
  /* 70 */, 0xb8, 0xfa, 0xdc, 0x31, 0x6b, 0xd1, 0xad, 0x19, 0x49, 0xbd, 0x51, 0x96, 0xee, 0xe4, 0xa8, 0x41
  /* 80 */, 0xda, 0xff, 0xcd, 0x55, 0x86, 0x36, 0xbe, 0x61, 0x52, 0xf8, 0xbb, 0x0e, 0x82, 0x48, 0x69, 0x9a
  /* 90 */, 0xe0, 0x47, 0x9e, 0x5c, 0x04, 0x4b, 0x34, 0x15, 0x79, 0x26, 0xa7, 0xde, 0x29, 0xae, 0x92, 0xd7
  /* a0 */, 0x84, 0xe9, 0xd2, 0xba, 0x5d, 0xf3, 0xc5, 0xb0, 0xbf, 0xa4, 0x3b, 0x71, 0x44, 0x46, 0x2b, 0xfc
  /* b0 */, 0xeb, 0x6f, 0xd5, 0xf6, 0x14, 0xfe, 0x7c, 0x70, 0x5a, 0x7d, 0xfd, 0x2f, 0x18, 0x83, 0x16, 0xa5
  /* c0 */, 0x91, 0x1f, 0x05, 0x95, 0x74, 0xa9, 0xc1, 0x5b, 0x4a, 0x85, 0x6d, 0x13, 0x07, 0x4f, 0x4e, 0x45
  /* d0 */, 0xb2, 0x0f, 0xc9, 0x1c, 0xa6, 0xbc, 0xec, 0x73, 0x90, 0x7b, 0xcf, 0x59, 0x8f, 0xa1, 0xf9, 0x2d
  /* e0 */, 0xf2, 0xb1, 0x00, 0x94, 0x37, 0x9f, 0xd0, 0x2e, 0x9c, 0x6e, 0x28, 0x3f, 0x80, 0xf0, 0x3d, 0xd3
  /* f0 */, 0x25, 0x8a, 0xb5, 0xe7, 0x42, 0xb3, 0xc7, 0xea, 0xf7, 0x4c, 0x11, 0x33, 0x03, 0xa2, 0xac, 0x60
};

/*
**    Type 1 substitution layer SL1 is an algorithm that takes a 16-byte
**    string x0 || x1 ||...|| x15 as input and outputs a 16-byte string
**    y0 || y1 ||...|| y15 as follows.
** 
**    y0 = SB1(x0),  y1 = SB2(x1),  y2 = SB3(x2),  y3 = SB4(x3),
**    y4 = SB1(x4),  y5 = SB2(x5),  y6 = SB3(x6),  y7 = SB4(x7),
**    y8 = SB1(x8),  y9 = SB2(x9),  y10= SB3(x10), y11= SB4(x11),
**    y12= SB1(x12), y13= SB2(x13), y14= SB3(x14), y15= SB4(x15).
*/

#define x0  ((x.left  >> 56)       )
#define x1  ((x.left  >> 48) & 0xff)
#define x2  ((x.left  >> 40) & 0xff)
#define x3  ((x.left  >> 32) & 0xff)
#define x4  ((x.left  >> 24) & 0xff)
#define x5  ((x.left  >> 16) & 0xff)
#define x6  ((x.left  >>  8) & 0xff)
#define x7  ((x.left       ) & 0xff)
#define x8  ((x.right >> 56)       )
#define x9  ((x.right >> 48) & 0xff)
#define x10 ((x.right >> 40) & 0xff)
#define x11 ((x.right >> 32) & 0xff)
#define x12 ((x.right >> 24) & 0xff)
#define x13 ((x.right >> 16) & 0xff)
#define x14 ((x.right >>  8) & 0xff)
#define x15 ((x.right      ) & 0xff)

static inline aria_u128_t aria_SL1 (aria_u128_t x)
{
  aria_u128_t y;

  y.left = 
     ((uint64_t )SB1[x0]  << 56)
   | ((uint64_t )SB2[x1]  << 48)
   | ((uint64_t )SB3[x2]  << 40)
   | ((uint64_t )SB4[x3]  << 32)
   | ((uint64_t )SB1[x4]  << 24)
   | ((uint64_t )SB2[x5]  << 16)
   | ((uint64_t )SB3[x6]  <<  8)
   |  (uint64_t )SB4[x7];

  y.right = 
     ((uint64_t )SB1[x8]  << 56)
   | ((uint64_t )SB2[x9]  << 48)
   | ((uint64_t )SB3[x10] << 40)
   | ((uint64_t )SB4[x11] << 32)
   | ((uint64_t )SB1[x12] << 24)
   | ((uint64_t )SB2[x13] << 16)
   | ((uint64_t )SB3[x14] <<  8)
   |  (uint64_t )SB4[x15];

  return y;
}

/*
**    Type 2 substitution layer SL2 is an algorithm that takes a 16-byte
**    string x0 || x1 ||...|| x15 as input and outputs a 16-byte string
**    y0 || y1 ||...|| y15 as follows.
** 
**    y0 = SB3(x0),  y1 = SB4(x1),  y2 = SB1(x2),  y3 = SB2(x3),
**    y4 = SB3(x4),  y5 = SB4(x5),  y6 = SB1(x6),  y7 = SB2(x7),
**    y8 = SB3(x8),  y9 = SB4(x9),  y10= SB1(x10), y11= SB2(x11),
**    y12= SB3(x12), y13= SB4(x13), y14= SB1(x14), y15= SB2(x15).
** 
**    Here, SB1, SB2, SB3, and SB4 are S-boxes that take an 8-bit string as
**    input and output an 8-bit string.  These S-boxes are defined by the
**    following look-up tables.
** 
*/

static inline aria_u128_t aria_SL2 (aria_u128_t x)
{
  aria_u128_t y;

  y.left = 
     ((uint64_t )SB3[x0]  << 56)
   | ((uint64_t )SB4[x1]  << 48)
   | ((uint64_t )SB1[x2]  << 40)
   | ((uint64_t )SB2[x3]  << 32)
   | ((uint64_t )SB3[x4]  << 24)
   | ((uint64_t )SB4[x5]  << 16)
   | ((uint64_t )SB1[x6]  <<  8)
   |  (uint64_t )SB2[x7];

  y.right = 
     ((uint64_t )SB3[x8]  << 56)
   | ((uint64_t )SB4[x9]  << 48)
   | ((uint64_t )SB1[x10] << 40)
   | ((uint64_t )SB2[x11] << 32)
   | ((uint64_t )SB3[x12] << 24)
   | ((uint64_t )SB4[x13] << 16)
   | ((uint64_t )SB1[x14] <<  8)
   |  (uint64_t )SB2[x15];

  return y;
}

/* 
**    Once W0, W1, W2, and W3 are determined, we compute encryption round
**    keys ek1, ..., ek17 as follows.
** 
**    ek1  = W0 ^(W1 >>> 19),
**    ek2  = W1 ^(W2 >>> 19),
**    ek3  = W2 ^(W3 >>> 19),
**    ek4  = (W0 >>> 19) ^ W3,
**    ek5  = W0 ^ (W1 >>> 31),
**    ek6  = W1 ^ (W2 >>> 31),
**    ek7  = W2 ^ (W3 >>> 31),
**    ek8  = (W0 >>> 31) ^ W3,
**    ek9  = W0 ^ (W1 <<< 61),
**    ek10 = W1 ^ (W2 <<< 61),
**    ek11 = W2 ^ (W3 <<< 61),
**    ek12 = (W0 <<< 61) ^ W3,
**    ek13 = W0 ^ (W1 <<< 31),
**    ek14 = W1 ^ (W2 <<< 31),
**    ek15 = W2 ^ (W3 <<< 31),
**    ek16 = (W0 <<< 31) ^ W3,
**    ek17 = W0 ^ (W1 <<< 19).
** 
*/

static inline void 
compute_ek (aria_u128_t W0
          , aria_u128_t W1
          , aria_u128_t W2
          , aria_u128_t W3
          , aria_u128_t ek[] /* out */)
{
  ek[ 1] = xor(W0, ror(W1, 19));
  ek[ 2] = xor(W1, ror(W2, 19));
  ek[ 3] = xor(W2, ror(W3, 19));
  ek[ 4] = xor(ror(W0, 19), W3);
  ek[ 5] = xor(W0, ror(W1, 31));
  ek[ 6] = xor(W1, ror(W2, 31));
  ek[ 7] = xor(W2, ror(W3, 31));
  ek[ 8] = xor(ror(W0, 31), W3);
  ek[ 9] = xor(W0, rol(W1, 61));
  ek[10] = xor(W1, rol(W2, 61));
  ek[11] = xor(W2, rol(W3, 61));
  ek[12] = xor(rol(W0, 61), W3);
  ek[13] = xor(W0, rol(W1, 31));
  ek[14] = xor(W1, rol(W2, 31));
  ek[15] = xor(W2, rol(W3, 31));
  ek[16] = xor(rol(W0, 31), W3);
  ek[17] = xor(W0, rol(W1, 19));
}

/*
** 2.4.3.  Diffusion Layer
** 
**    Diffusion layer A is an algorithm that takes a 16-byte string x0 ||
**    x1 || ... || x15 as input and outputs a 16-byte string
**    y0 || y1 ||...|| y15 by the following equations.
** 
**       y0  = x3 ^ x4 ^ x6 ^ x8  ^ x9  ^ x13 ^ x14,
**       y1  = x2 ^ x5 ^ x7 ^ x8  ^ x9  ^ x12 ^ x15,
**       y2  = x1 ^ x4 ^ x6 ^ x10 ^ x11 ^ x12 ^ x15,
**       y3  = x0 ^ x5 ^ x7 ^ x10 ^ x11 ^ x13 ^ x14,
**       y4  = x0 ^ x2 ^ x5 ^ x8  ^ x11 ^ x14 ^ x15,
**       y5  = x1 ^ x3 ^ x4 ^ x9  ^ x10 ^ x14 ^ x15,
**       y6  = x0 ^ x2 ^ x7 ^ x9  ^ x10 ^ x12 ^ x13,
**       y7  = x1 ^ x3 ^ x6 ^ x8  ^ x11 ^ x12 ^ x13,
**       y8  = x0 ^ x1 ^ x4 ^ x7  ^ x10 ^ x13 ^ x15,
**       y9  = x0 ^ x1 ^ x5 ^ x6  ^ x11 ^ x12 ^ x14,
**       y10 = x2 ^ x3 ^ x5 ^ x6  ^ x8  ^ x13 ^ x15,
**       y11 = x2 ^ x3 ^ x4 ^ x7  ^ x9  ^ x12 ^ x14,
**       y12 = x1 ^ x2 ^ x6 ^ x7  ^ x9  ^ x11 ^ x12,
**       y13 = x0 ^ x3 ^ x6 ^ x7  ^ x8  ^ x10 ^ x13,
**       y14 = x0 ^ x3 ^ x4 ^ x5  ^ x9  ^ x11 ^ x14,
**       y15 = x1 ^ x2 ^ x4 ^ x5  ^ x8  ^ x10 ^ x15.
** 
**    Note that A is an involution.  That is, for any 16-byte input string
**    x, x = A(A(x)) holds.
** 
*/

static inline aria_u128_t aria_A (aria_u128_t x)
{
  aria_u128_t y;
#if 0
  /* For 1000000 iterations: 1315.81 ns (1315.75 ns) per iteration with 0 errors */
  y.left = 
     ((uint64_t )(x3 ^ x4 ^ x6 ^ x8  ^ x9  ^ x13 ^ x14) << 56)
   | ((uint64_t )(x2 ^ x5 ^ x7 ^ x8  ^ x9  ^ x12 ^ x15) << 48)
   | ((uint64_t )(x1 ^ x4 ^ x6 ^ x10 ^ x11 ^ x12 ^ x15) << 40)
   | ((uint64_t )(x0 ^ x5 ^ x7 ^ x10 ^ x11 ^ x13 ^ x14) << 32)
   | ((uint64_t )(x0 ^ x2 ^ x5 ^ x8  ^ x11 ^ x14 ^ x15) << 24)
   | ((uint64_t )(x1 ^ x3 ^ x4 ^ x9  ^ x10 ^ x14 ^ x15) << 16)
   | ((uint64_t )(x0 ^ x2 ^ x7 ^ x9  ^ x10 ^ x12 ^ x13) <<  8)
   |  (uint64_t )(x1 ^ x3 ^ x6 ^ x8  ^ x11 ^ x12 ^ x13);

  y.right = 
     ((uint64_t )(x0 ^ x1 ^ x4 ^ x7  ^ x10 ^ x13 ^ x15) << 56)
   | ((uint64_t )(x0 ^ x1 ^ x5 ^ x6  ^ x11 ^ x12 ^ x14) << 48)
   | ((uint64_t )(x2 ^ x3 ^ x5 ^ x6  ^ x8  ^ x13 ^ x15) << 40)
   | ((uint64_t )(x2 ^ x3 ^ x4 ^ x7  ^ x9  ^ x12 ^ x14) << 32)
   | ((uint64_t )(x1 ^ x2 ^ x6 ^ x7  ^ x9  ^ x11 ^ x12) << 24)
   | ((uint64_t )(x0 ^ x3 ^ x6 ^ x7  ^ x8  ^ x10 ^ x13) << 16)
   | ((uint64_t )(x0 ^ x3 ^ x4 ^ x5  ^ x9  ^ x11 ^ x14) <<  8)
   |  (uint64_t )(x1 ^ x2 ^ x4 ^ x5  ^ x8  ^ x10 ^ x15);
#else
  /* For 1000000 iterations: 1104.03 ns (1104.03 ns) per iteration with 0 errors */
  /* eliminate some common subexpressions */
  uint8_t t0 = x0 ^ x7 ^ x10 ^ x13;
  uint8_t t1 = x1 ^ x6 ^ x11 ^ x12;
  uint8_t t2 = x2 ^ x5 ^ x8  ^ x15;
  uint8_t t3 = x3 ^ x4 ^ x9  ^ x14;

  y.left = 
     ((uint64_t )(t3      ^ x6 ^ x8        ^ x13      ) << 56)
   | ((uint64_t )(t2      ^ x7       ^ x9  ^ x12      ) << 48)
   | ((uint64_t )(t1 ^ x4      ^ x10             ^ x15) << 40)
   | ((uint64_t )(t0 ^ x5            ^ x11       ^ x14) << 32)
   | ((uint64_t )(x0 ^ t2            ^ x11 ^ x14      ) << 24)
   | ((uint64_t )(x1 ^ t3            ^ x10       ^ x15) << 16)
   | ((uint64_t )(t0 ^ x2      ^ x9        ^ x12      ) <<  8)
   |  (uint64_t )(t1 ^ x3      ^ x8              ^ x13);

  y.right = 
     ((uint64_t )(t0 ^ x1 ^ x4                   ^ x15) << 56)
   | ((uint64_t )(x0 ^ t1 ^ x5                   ^ x14) << 48)
   | ((uint64_t )(t2 ^ x3      ^ x6        ^ x13      ) << 40)
   | ((uint64_t )(x2 ^ t3      ^ x7        ^ x12      ) << 32)
   | ((uint64_t )(t1 ^ x2      ^ x7  ^ x9             ) << 24)
   | ((uint64_t )(t0 ^ x3 ^ x6       ^ x8             ) << 16)
   | ((uint64_t )(x0 ^ t3      ^ x5        ^ x11      ) <<  8)
   |  (uint64_t )(x1 ^ t2 ^ x4             ^ x10      );
#endif

  return y;
}

/* 
** 2.4.1.  Round Functions
** 
**    There are two types of round functions for ARIA.  One is called an
**    odd round function and is denoted by FO.  It takes as input a pair
**    (D,RK) of two 128-bit strings and outputs
** 
**    FO(D,RK) = A(SL1(D ^ RK)).
** 
**    The other is called an even round function and is denoted by FE.  It
**    takes as input a pair (D,RK) of two 128-bit strings and outputs
** 
**    FE(D,RK) = A(SL2(D ^ RK)).
** 
**    Functions SL1 and SL2, called substitution layers, are described in
**    Section 2.4.2.  Function A, called a diffusion layer, is described in
**    Section 2.4.3.
*/

static inline aria_u128_t aria_FO (aria_u128_t d, aria_u128_t rk)
{
  return aria_A(aria_SL1(xor(d, rk)));
}

static inline aria_u128_t aria_FE (aria_u128_t d, aria_u128_t rk)
{
  return aria_A(aria_SL2(xor(d, rk)));
}

/*
** 2.3.1.1.  Encryption for 128-Bit Keys
** 
**    Let P be a 128-bit plaintext and K be a 128-bit master key.  Let ek1,
**    ..., ek13 be the encryption round keys defined by K.  Then the
**    ciphertext C is computed by the following algorithm.
** 
**    P1  = FO(P  , ek1 );              // Round 1
**    P2  = FE(P1 , ek2 );              // Round 2
**    P3  = FO(P2 , ek3 );              // Round 3
**    P4  = FE(P3 , ek4 );              // Round 4
**    P5  = FO(P4 , ek5 );              // Round 5
**    P6  = FE(P5 , ek6 );              // Round 6
**    P7  = FO(P6 , ek7 );              // Round 7
**    P8  = FE(P7 , ek8 );              // Round 8
**    P9  = FO(P8 , ek9 );              // Round 9
**    P10 = FE(P9 , ek10);              // Round 10
**    P11 = FO(P10, ek11);              // Round 11
**    C   = SL2(P11 ^ ek12) ^ ek13;     // Round 12
** 
** 2.3.1.2.  Encryption for 192-Bit Keys
** 
**    Let P be a 128-bit plaintext and K be a 192-bit master key.  Let ek1,
**    ..., ek15 be the encryption round keys defined by K.  Then the
**    ciphertext C is computed by the following algorithm.
** 
**    P1  = FO(P  , ek1 );              // Round 1
**    P2  = FE(P1 , ek2 );              // Round 2
**    P3  = FO(P2 , ek3 );              // Round 3
**    P4  = FE(P3 , ek4 );              // Round 4
**    P5  = FO(P4 , ek5 );              // Round 5
**    P6  = FE(P5 , ek6 );              // Round 6
**    P7  = FO(P6 , ek7 );              // Round 7
**    P8  = FE(P7 , ek8 );              // Round 8
**    P9  = FO(P8 , ek9 );              // Round 9
**    P10 = FE(P9 , ek10);              // Round 10
**    P11 = FO(P10, ek11);              // Round 11
**    P12 = FE(P11, ek12);              // Round 12
**    P13 = FO(P12, ek13);              // Round 13
**    C   = SL2(P13 ^ ek14) ^ ek15;     // Round 14
** 
** 2.3.1.3.  Encryption for 256-Bit Keys
** 
**    Let P be a 128-bit plaintext and K be a 256-bit master key.  Let ek1,
**    ..., ek17 be the encryption round keys defined by K.  Then the
**    ciphertext C is computed by the following algorithm.
** 
**    P1 = FO(P  , ek1 );              // Round 1
**    P2 = FE(P1 , ek2 );              // Round 2
**    P3 = FO(P2 , ek3 );              // Round 3
**    P4 = FE(P3 , ek4 );              // Round 4
**    P5 = FO(P4 , ek5 );              // Round 5
**    P6 = FE(P5 , ek6 );              // Round 6
**    P7 = FO(P6 , ek7 );              // Round 7
**    P8 = FE(P7 , ek8 );              // Round 8
**    P9 = FO(P8 , ek9 );              // Round 9
**    P10= FE(P9 , ek10);              // Round 10
**    P11= FO(P10, ek11);              // Round 11
**    P12= FE(P11, ek12);              // Round 12
**    P13= FO(P12, ek13);              // Round 13
**    P14= FE(P13, ek14);              // Round 14
**    P15= FO(P14, ek15);              // Round 15
**    C  = SL2(P15 ^ ek16) ^ ek17;     // Round 16
*/

static inline aria_u128_t 
aria_crypt (uint8_t rounds, aria_u128_t ek[], aria_u128_t Plaintext)
{
  aria_u128_t P = aria_FO(Plaintext, ek[1]);
  for (int i = 2; i < rounds; )
  {
    P = aria_FE(P, ek[i++]);
    P = aria_FO(P, ek[i++]);
  }
  return xor(aria_SL2(xor(P, ek[rounds])), ek[rounds + 1]);
}

/*
** 2.2.  Key Scheduling Part
** 
**    Let K denote a master key of 128, 192, or 256 bits.  Given the master
**    key K, we first define 128-bit values KL and KR as follows.
** 
**    KL || KR = K || 0 ... 0,
** 
**    where the number of zeros is 128, 64, or 0, depending on the size of
**    K.  That is, KL is set to the leftmost 128 bits of K and KR is set to
**    the remaining bits of K (if any), right-padded with zeros to a
**    128-bit value.  Then, we define four 128-bit values (W0, W1, W2, and
**    W3) as the intermediate round values appearing in the encryption of
**    KL || KR by a 3-round, 256-bit Feistel cipher.
** 
**    W0 = KL,
**    W1 = FO(W0, CK1) ^ KR,
**    W2 = FE(W1, CK2) ^ W0,
**    W3 = FO(W2, CK3) ^ W1.
** 
**    Here, FO and FE, respectively called odd and even round functions,
**    are defined in Section 2.4.1.  CK1, CK2, and CK3 are 128-bit
**    constants, taking one of the following values.
** 
**    C1 =  0x517cc1b727220a94fe13abe8fa9a6ee0
**    C2 =  0x6db14acc9e21c820ff28b1d5ef5de2b0
**    C3 =  0xdb92371d2126e9700324977504e8c90e
** 
**    These values are obtained from the first 128*3 bits of the fractional
**    part of 1/PI, where PI is the circle ratio.  Now the constants CK1,
**    CK2, and CK3 are defined by the following table.
** 
**        Key size  CK1  CK2  CK3
**          128     C1   C2   C3
**          192     C2   C3   C1
**          256     C3   C1   C2
** 
**    For example, if the key size is 192 bits, CK1 = C2, CK2 = C3, and
**    CK3 = C1.
*/

static const aria_u128_t C1 = { 0x517cc1b727220a94, 0xfe13abe8fa9a6ee0 };
static const aria_u128_t C2 = { 0x6db14acc9e21c820, 0xff28b1d5ef5de2b0 };
static const aria_u128_t C3 = { 0xdb92371d2126e970, 0x0324977504e8c90e };

aria_u128_t 
aria_encrypt_128 (aria_u128_t Key, aria_u128_t Plaintext)
{
  aria_u128_t ek[18];

  aria_u128_t W0 = Key;
  aria_u128_t W1 =     aria_FO(W0, C1);
  aria_u128_t W2 = xor(aria_FE(W1, C2), W0);
  aria_u128_t W3 = xor(aria_FO(W2, C3), W1);

  compute_ek(W0, W1, W2, W3, ek);

  return aria_crypt(12u, ek, Plaintext);
}

aria_u128_t 
aria_encrypt_192 (aria_u128_t KeyLeft, aria_u128_t KeyRight, aria_u128_t Plaintext)
{
  aria_u128_t ek[18];

  aria_u128_t W0 = KeyLeft;
  aria_u128_t W1 = xor(aria_FO(W0, C2), KeyRight);
  aria_u128_t W2 = xor(aria_FE(W1, C3), W0);
  aria_u128_t W3 = xor(aria_FO(W2, C1), W1);

  compute_ek(W0, W1, W2, W3, ek);

  return aria_crypt(14u, ek, Plaintext);
}

aria_u128_t 
aria_encrypt_256 (aria_u128_t KeyLeft, aria_u128_t KeyRight, aria_u128_t Plaintext)
{
  aria_u128_t ek[18];

  aria_u128_t W0 = KeyLeft;
  aria_u128_t W1 = xor(aria_FO(W0, C3), KeyRight);
  aria_u128_t W2 = xor(aria_FE(W1, C1), W0);
  aria_u128_t W3 = xor(aria_FO(W2, C2), W1);

  compute_ek(W0, W1, W2, W3, ek);

  return aria_crypt(16u, ek, Plaintext);
}

/*
**    The number of rounds depends on the size of the master key as
**    follows.
** 
**         Key size     Number of Rounds
**          128              12
**          192              14
**          256              16
** 
**    Due to an extra key addition layer in the last round, 12-, 14-, and
**    16-round algorithms require 13, 15, and 17 round keys, respectively.
** 
**    Decryption round keys are derived from the encryption round keys.
** 
**    dk1 = ek{n+1},
**    dk2 = A(ek{n}),
**    dk3 = A(ek{n-1}),
**    ...,
**    dk{n}= A(ek2),
**    dk{n+1}= ek1.
** 
**    Here, A and n denote the diffusion layer of ARIA and the number of
**    rounds, respectively.  The diffusion layer A is defined in Section
**    2.4.3.
*/
/* 
** 2.3.2.  Decryption Process
** 
**    The decryption process of ARIA is the same as the encryption process
**    except that encryption round keys are replaced by decryption round
**    keys.  For example, encryption round keys ek1, ..., ek13 of the
**    12-round ARIA algorithm are replaced by decryption round keys dk1,
**    ..., dk13, respectively.
*/

aria_u128_t 
aria_decrypt_128 (aria_u128_t Key, aria_u128_t Ciphertext)
{
  aria_u128_t ek[18];

  aria_u128_t W0 = Key;
  aria_u128_t W1 =     aria_FO(W0, C1);
  aria_u128_t W2 = xor(aria_FE(W1, C2), W0);
  aria_u128_t W3 = xor(aria_FO(W2, C3), W1);

  compute_ek(W0, W1, W2, W3, ek);

  ek[ 0] = ek[13];
  ek[13] = ek[ 1];
  ek[ 1] = ek[ 0];

  for (int i = 2, j = 12; i < j; i++, j--)
  {
    ek[ 0] = ek[ j];
    ek[ j] = aria_A(ek[ i]);
    ek[ i] = aria_A(ek[ 0]);
  }
  ek[7] = aria_A(ek[ 7]);

  return aria_crypt(12u, ek, Ciphertext);
}

aria_u128_t 
aria_decrypt_192 (aria_u128_t KeyLeft, aria_u128_t KeyRight, aria_u128_t Ciphertext)
{
  aria_u128_t ek[18];

  aria_u128_t W0 = KeyLeft;
  aria_u128_t W1 = xor(aria_FO(W0, C2), KeyRight);
  aria_u128_t W2 = xor(aria_FE(W1, C3), W0);
  aria_u128_t W3 = xor(aria_FO(W2, C1), W1);

  compute_ek(W0, W1, W2, W3, ek);

  ek[ 0] = ek[15];
  ek[15] = ek[ 1];
  ek[ 1] = ek[ 0];

  for (int i = 2, j = 14; i < j; i++, j--)
  {
    ek[ 0] = ek[ j];
    ek[ j] = aria_A(ek[ i]);
    ek[ i] = aria_A(ek[ 0]);
  }
  ek[8] = aria_A(ek[ 8]);

  return aria_crypt(14u, ek, Ciphertext);
}

aria_u128_t 
aria_decrypt_256 (aria_u128_t KeyLeft, aria_u128_t KeyRight, aria_u128_t Ciphertext)
{
  aria_u128_t ek[18];

  aria_u128_t W0 = KeyLeft;
  aria_u128_t W1 = xor(aria_FO(W0, C3), KeyRight);
  aria_u128_t W2 = xor(aria_FE(W1, C1), W0);
  aria_u128_t W3 = xor(aria_FO(W2, C2), W1);

  compute_ek(W0, W1, W2, W3, ek);

  ek[ 0] = ek[17];
  ek[17] = ek[ 1];
  ek[ 1] = ek[ 0];

  for (int i = 2, j = 16; i < j; i++, j--)
  {
    ek[ 0] = ek[ j];
    ek[ j] = aria_A(ek[ i]);
    ek[ i] = aria_A(ek[ 0]);
  }
  ek[9] = aria_A(ek[ 9]);

  return aria_crypt(16u, ek, Ciphertext);
}


#ifdef ARIA_TEST

/*
** Appendix A.  Example Data of ARIA
** 
**    Here are test data for ARIA in hexadecimal form.
** 
** A.1.  128-Bit Key
** 
**    - Key       : 000102030405060708090a0b0c0d0e0f
**    - Plaintext : 00112233445566778899aabbccddeeff
**    - Ciphertext: d718fbd6ab644c739da95f3be6451778
** 
**    - Round key generators
**       W0: 000102030405060708090a0b0c0d0e0f
**       W1: 2afbea741e1746dd55c63ba1afcea0a5
**       W2: 7c8578018bb127e02dfe4e78c288e33c
**       W3: 6785b52b74da46bf181054082763ff6d
** 
**    - Encryption round keys
**       e1:  d415a75c794b85c5e0d2a0b3cb793bf6
**       e2:  369c65e4b11777ab713a3e1e6601b8f4
**       e3:  0368d4f13d14497b6529ad7ac809e7d0
**       e4:  c644552b549a263fb8d0b50906229eec
**       e5:  5f9c434951f2d2ef342787b1a781794c
**       e6:  afea2c0ce71db6de42a47461f4323c54
**       e7:  324286db44ba4db6c44ac306f2a84b2c
**       e8:  7f9fa93574d842b9101a58063771eb7b
**       e9:  aab9c57731fcd213ad5677458fcfe6d4
**       e10: 2f4423bb06465abada5694a19eb88459
**       e11: 9f8772808f5d580d810ef8ddac13abeb
**       e12: 8684946a155be77ef810744847e35fad
**       e13: 0f0aa16daee61bd7dfee5a599970fb35
** 
**    - Intermediate round values
**       P1:  7fc7f12befd0a0791de87fa96b469f52
**       P2:  ac8de17e49f7c5117618993162b189e9
**       P3:  c3e8d59ec2e62d5249ca2741653cb7dd
**       P4:  5d4aebb165e141ff759f669e1e85cc45
**       P5:  7806e469f68874c5004b5f4a046bbcfa
**       P6:  110f93c9a630cdd51f97d2202413345a
**       P7:  e054428ef088fef97928241cd3be499e
**       P8:  5734f38ea1ca3ddd102e71f95e1d5f97
**       P9:  4903325be3e500cccd52fba4354a39ae
**       P10: cb8c508e2c4f87880639dc896d25ec9d
**       P11: e7e0d2457ed73d23d481424095afdca0
** 
** A.2.  192-Bit Key
** 
**    Key       : 000102030405060708090a0b0c0d0e0f
**                1011121314151617
**    Plaintext : 00112233445566778899aabbccddeeff
**    Ciphertext: 26449c1805dbe7aa25a468ce263a9e79
** 
** A.3.  256-Bit Key
** 
**    Key       : 000102030405060708090a0b0c0d0e0f
**                101112131415161718191a1b1c1d1e1f
**    Plaintext : 00112233445566778899aabbccddeeff
**    Ciphertext: f92bd7c79fb72e2f2b8f80c1972d24fc
** */

int main (int argc, char **argv)
{
  if ((argc == 2) && (0 == strcmp("-s", argv[1])))
  {
    aria_u128_t KeyLeft    = { 0x0001020304050607, 0x08090a0b0c0d0e0f };
    aria_u128_t KeyRight;
    aria_u128_t Plaintext  = { 0x0011223344556677, 0x8899aabbccddeeff };
    aria_u128_t Ciphertext = { 0xd718fbd6ab644c73, 0x9da95f3be6451778 };

    aria_u128_t C = aria_encrypt_128(KeyLeft, Plaintext);

    if (0 == memcmp((const void *)&Ciphertext, (const void *)&C, sizeof(aria_u128_t)))
    {
      printf("aria_encrypt_128 pass\n");
    }
    else
    {
      fprintf(stderr, "aria_encrypt_128 fail: ");
      print_aria_u128(C);
      fprintf(stderr, "\n");
    }

    aria_u128_t P = aria_decrypt_128(KeyLeft, Ciphertext);

    if (0 == memcmp((const void *)&Plaintext, (const void *)&P, sizeof(aria_u128_t)))
    {
      printf("aria_decrypt_128 pass\n");
    }
    else
    {
      fprintf(stderr, "aria_decrypt_128 fail: ");
      print_aria_u128(P);
      fprintf(stderr, "\n");
    }    

    KeyLeft    = (aria_u128_t ){ 0x0001020304050607, 0x08090a0b0c0d0e0f };
    KeyRight   = (aria_u128_t ){ 0x1011121314151617, 0x0000000000000000 };
    Plaintext  = (aria_u128_t ){ 0x0011223344556677, 0x8899aabbccddeeff };
    Ciphertext = (aria_u128_t ){ 0x26449c1805dbe7aa, 0x25a468ce263a9e79 };

    C = aria_encrypt_192(KeyLeft, KeyRight, Plaintext);

    if (0 == memcmp((const void *)&Ciphertext, (const void *)&C, sizeof(aria_u128_t)))
    {
      printf("aria_encrypt_192 pass\n");
    }
    else
    {
      fprintf(stderr, "aria_encrypt_192 fail: ");
      print_aria_u128(C);
      fprintf(stderr, "\n");
    }

    P = aria_decrypt_192(KeyLeft, KeyRight, Ciphertext);

    if (0 == memcmp((const void *)&Plaintext, (const void *)&P, sizeof(aria_u128_t)))
    {
      printf("aria_decrypt_192 pass\n");
    }
    else
    {
      fprintf(stderr, "aria_decrypt_192 fail: ");
      print_aria_u128(P);
      fprintf(stderr, "\n");
    }

    KeyLeft    = (aria_u128_t ){ 0x0001020304050607, 0x08090a0b0c0d0e0f };
    KeyRight   = (aria_u128_t ){ 0x1011121314151617, 0x18191a1b1c1d1e1f };
    Plaintext  = (aria_u128_t ){ 0x0011223344556677, 0x8899aabbccddeeff };
    Ciphertext = (aria_u128_t ){ 0xf92bd7c79fb72e2f, 0x2b8f80c1972d24fc };

    C = aria_encrypt_256(KeyLeft, KeyRight, Plaintext);

    if (0 == memcmp((const void *)&Ciphertext, (const void *)&C, sizeof(aria_u128_t)))
    {
      printf("aria_encrypt_256 pass\n");
    }
    else
    {
      fprintf(stderr, "aria_encrypt_256 fail: ");
      print_aria_u128(C);
      fprintf(stderr, "\n");
    }

    P = aria_decrypt_256(KeyLeft, KeyRight, Ciphertext);

    if (0 == memcmp((const void *)&Plaintext, (const void *)&P, sizeof(aria_u128_t)))
    {
      printf("aria_decrypt_256 pass\n");
    }
    else
    {
      fprintf(stderr, "aria_decrypt_256 fail: ");
      print_aria_u128(P);
      fprintf(stderr, "\n");
    }

  }
  else if ((argc == 2) && (0 == strcmp("-t", argv[1])))
  {

    (void)xorshift128plus_seed(0x5a5a5a5a5a5a5a5au);

    const uint32_t iterations = 1000000u;

    uint32_t errors = 0u;

    double startm = timer_e_nanoseconds();
#if 0
    double startg = timer_e_nanoseconds_gtod();
#endif

    for (uint32_t i = 0u; i < iterations; i++)
    {
      aria_u128_t KeyLeft    = (aria_u128_t ){ xorshift128plus_next(), xorshift128plus_next() };
      aria_u128_t KeyRight   = (aria_u128_t ){ xorshift128plus_next(), xorshift128plus_next() };
      aria_u128_t Plaintext  = (aria_u128_t ){ xorshift128plus_next(), xorshift128plus_next() };

      aria_u128_t Ciphertext = aria_encrypt_256(KeyLeft, KeyRight, Plaintext);

      aria_u128_t P = aria_decrypt_256(KeyLeft, KeyRight, Ciphertext);

      if (0 != memcmp((const void *)&Plaintext, (const void *)&P, sizeof(aria_u128_t)))
      {
        errors++;
      }
    }

    double endm = timer_e_nanoseconds();
#if 0
    double endg = timer_e_nanoseconds_gtod();

    fprintf(stderr, "For %u iterations: %g ns (%g ns) per iteration with %u errors\n"
                  , iterations
                  , (endm - startm) / iterations
                  , (endg - startg) / iterations
                  , errors
            );
#else
    fprintf(stderr, "For %u iterations: %g ns per iteration with %u errors\n"
                  , iterations
                  , (endm - startm) / iterations
                  , errors
            );
#endif
  }
}

#endif
