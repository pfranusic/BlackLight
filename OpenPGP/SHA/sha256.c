// sha256.c
// Partial implementation of the secure hash algorithm SHA-256
// as specified in the various sections of NIST FIPS PUB 180-2.
// Copyright 2012 Pete Franusic
//


//
// ulong
//

typedef unsigned long ulong;


// 
// sha256_H
// This 8 by 32-bit word block is specified in section 5.3.2.
// It is declared in sha.lisp by sha256-malloc.
// A pointer to this block is passed in sha256_calc.
//
// static ulong sha256_H [8];


// 
// sha256_W
// This 64-word message schedule is specified in section 6.2.
// It is declared in sha.lisp by sha256-malloc.
// A pointer to this block is passed in sha256_calc.
//
// static ulong sha256_W [64];


//
// sha256_K
// These 64 SHA-256 constants are specified in section 4.2.3.
// They are declared here rather than in sha.lisp.
//

static ulong sha256_K [64] =
  {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };


//
// Operations on Words
// the general SHA operators specified in section 3.2
// 

static ulong SHR (int n, ulong x)
{
  int i;
  ulong w = x;
  for (i=n; i>0; i--)
    {
      w = w >> 1;
      w = w & 0x7FFFFFFF;
    }
  return w;
}

static ulong ROTR (int n, ulong x)
{
  int i;
  ulong w = x;
  for (i=n; i>0; i--)
    {
      if (w & 1)
	{
	  w = w >> 1;
	  w = w | 0x80000000;
	}
      else
	{
	  w = w >> 1;
	  w = w & 0x7FFFFFFF;
	}
    }
  return w;
}


//
// SHA-256 Functions
// the functions specified in section 4.1.2
//

static ulong sha256_Ch (ulong x, ulong y, ulong z)
{
  ulong w;
  w = (x & y) ^ (~x & z);
  return w;
}

static ulong sha256_Maj (ulong x, ulong y, ulong z)
{
  ulong w;
  w = (x & y) ^ (x & z) ^ (y & z);
  return w;
}

static sha256_bs0 (ulong x)
{
  return (ROTR(2,x) ^ ROTR(13,x) ^ ROTR(22,x));
}


static sha256_bs1 (ulong x)
{
  return (ROTR(6,x) ^ ROTR(11,x) ^ ROTR(25,x));
}


static sha256_ls0 (ulong x)
{
  return (ROTR(7,x) ^ ROTR(18,x) ^ SHR(3,x));
}


static sha256_ls1 (ulong x)
{
  return (ROTR(17,x) ^ ROTR(19,x) ^ SHR(10,x));
}



//
// sha256_calc
// processes each message block of 16 words.
// Before sha256_calc is called,
// the 16 words of sha256_H must be valid,
// and the first 16 words of sha256_W must contain the message block.
// sha256_calc operates on the entire message schedule sha256_W,
// calculates an intermediate hash and leaves it in sha256_H,
// and finally returns an integer error code.
//

int sha256_calc (ulong* sha256_H, ulong* sha256_W)
{
  // Declare local variables.
  ulong a, b, c, d, e, f, g, h, x1, x2;
  int i, t;

  // "Prepare the message schedule."
  // Note: The caller initializes the first 16 words.
  for (t=16; t<64; t++)
    sha256_W [t] = sha256_ls1 (sha256_W [t-2]) + sha256_W [t-7] + \
      sha256_ls0 (sha256_W [t-15]) + sha256_W [t-16];

  // "Initialize the eight working variables."
  a = sha256_H [0];
  b = sha256_H [1];
  c = sha256_H [2];
  d = sha256_H [3];
  e = sha256_H [4];
  f = sha256_H [5];
  g = sha256_H [6];
  h = sha256_H [7];

  // "For t = 0 to 63:"
  for (t=0; t<64; t++)
    {
      x1 = h + sha256_bs1 (e) + sha256_Ch (e, f, g) + sha256_K [t] + sha256_W [t];
      x2 = sha256_bs0 (a) + sha256_Maj (a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + x1;
      d = c;
      c = b;
      b = a;
      a = x1 + x2;
    }

  // "Compute the ith intermediate hash value."
  sha256_H [0] += a;
  sha256_H [1] += b;
  sha256_H [2] += c;
  sha256_H [3] += d;
  sha256_H [4] += e;
  sha256_H [5] += f;
  sha256_H [6] += g;
  sha256_H [7] += h;

  // Return the error code.
  return 0;
}

