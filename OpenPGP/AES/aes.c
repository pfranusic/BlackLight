//// aes.c
//// An abbreviated implementation of AES-128 cryptographic algorithm.
//// Includes only the KeyExpand function and the Cipher function.
//// Does not include the InvCipher function.  Instead,
//// includes an OpenPGP CFB encode function and OpenPGP CFB decode function.
//// aes_128_expand is the public KeyExpand function.
//// aes_128_cipher is the public Cipher function.
//// aes_128_cfbe is the public AES-128 cipher function plus CFB encode.
//// aes_128_cfbd is the public AES-128 cipher function plus CFB decode.
//// Copyright 2012 Pete Franusic.
////


////
//// Definitions
//// A ulong is an unsigned 32-bit register.
//// A uchar is an unsigned 8-bit value.
//// A huge is a pointer to an array of integers.
////

#define Nb 4
#define Nk 4
#define Nr 10
typedef unsigned long ulong;
typedef unsigned char uchar;
typedef ulong* huge;


////
//// w 
//// the key schedule based on the original key.
//// It is created using the KeyExpansion function.
//// For Nk=4, w has 44 elements.
////

// static ulong w[Nb*(Nr+1)];
static huge w; // NEW


////
//// bufform
////

struct OCTET_FORM
{
  unsigned b0 : 8 ;
  unsigned b1 : 8 ;
  unsigned b2 : 8 ;
  unsigned b3 : 8 ;
};

union bufform
{
  struct OCTET_FORM octet;
  ulong value;
};


////
//// sbox
////

static unsigned char sbox [] =
  {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
  };


////
//// RotWord
//// takes a 32-bit word and performs a "cyclic permutation."
//// That is, it rotates everything 8 bits to the left.
////

static ulong RotWord (ulong x)
{
  ulong msb, y;
  msb = (x >> 24) & 0xFF;
  y = (x << 8) & 0xFFFFFF00;
  y = y | msb;
  return y;
}


////
//// SubWord
//// takes a 32-bit word and, on each of the four bytes,
//// performs a byte substitution using the sbox table,
//// where the original byte is the address.
////

static ulong SubWord (ulong x)
{
  union bufform y;
  y.value = x;
  y.octet.b0 = sbox [y.octet.b0];
  y.octet.b1 = sbox [y.octet.b1];
  y.octet.b2 = sbox [y.octet.b2];
  y.octet.b3 = sbox [y.octet.b3];
  return (y.value);
}


////
//// Rcon
//// These are the round constants for Nr = 10.
////

static ulong Rcon [Nr+1] =
  {
    0x00000000,
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000
  };


////
//// SubBytes
//// applies the S-Box to each byte of the 16-byte state.
////

static void SubBytes (huge x)
{
  union bufform y;
  int i;

  for (i=0; i<Nb; i++)
    {
      y.value = x[i];
      y.octet.b0 = sbox [y.octet.b0];
      y.octet.b1 = sbox [y.octet.b1];
      y.octet.b2 = sbox [y.octet.b2];
      y.octet.b3 = sbox [y.octet.b3];
      x[i] = y.value;
    }
}


////
//// ShiftRows
//// cyclically shifts the last three rows in the state.
////

static void ShiftRows (huge s)
{
  union bufform x;
  char a[4][4], b[4][4];
  int row;

  for (row=0; row<4; row++)
    {
      x.value = s[row];
      a[row][0] = x.octet.b0;
      a[row][1] = x.octet.b1;
      a[row][2] = x.octet.b2;
      a[row][3] = x.octet.b3;
    }

  b[0][0] = a[0][0];
  b[0][1] = a[1][1];
  b[0][2] = a[2][2];
  b[0][3] = a[3][3];
  b[1][0] = a[1][0];
  b[1][1] = a[2][1];
  b[1][2] = a[3][2];
  b[1][3] = a[0][3];
  b[2][0] = a[2][0];
  b[2][1] = a[3][1];
  b[2][2] = a[0][2];
  b[2][3] = a[1][3];
  b[3][0] = a[3][0];
  b[3][1] = a[0][1];
  b[3][2] = a[1][2];
  b[3][3] = a[2][3];

  for (row=0; row<4; row++)
    {
      x.octet.b0 = b[row][0];
      x.octet.b1 = b[row][1];
      x.octet.b2 = b[row][2];
      x.octet.b3 = b[row][3];
      s[row] = x.value;
    }
}


////
//// xtime
////

static int xtime (int x)
{
  int y;
  if (x & 0x80)
    {
      y = x << 1;
      y &= 0xFF;
      y ^= 0x1B;
      return y;
    }
  else
    {
      y = x << 1;
      y &= 0xFF;
      return y;
    }      
}


////
//// MixColumns
//// operates on the State column-by-column.
//// It takes all of the columns of the State and 
//// mixes their data, independently of one another,
//// to produce new columns.

static void MixColumns (huge state)
{
  uchar* s = (uchar*) state;// point to a block of 16 bytes
  uchar s0_1, s1_1, s2_1, s3_1;// the {01}*s bytes
  uchar s0_2, s1_2, s2_2, s3_2;// the {02}*s bytes
  uchar s0_3, s1_3, s2_3, s3_3;// the {03}*s bytes
  int row;

  for (row=0; row<4; row++, s+=4)
    {
      s0_1 = s[0];
      s1_1 = s[1];
      s2_1 = s[2];
      s3_1 = s[3];

      s0_2 = xtime (s0_1);
      s1_2 = xtime (s1_1);
      s2_2 = xtime (s2_1);
      s3_2 = xtime (s3_1);

      s0_3 = s0_2 ^ s0_1;
      s1_3 = s1_2 ^ s1_1;
      s2_3 = s2_2 ^ s2_1;
      s3_3 = s3_2 ^ s3_1;

      s[0] = s0_2 ^ s1_3 ^ s2_1 ^ s3_1;
      s[1] = s0_1 ^ s1_2 ^ s2_3 ^ s3_1;
      s[2] = s0_1 ^ s1_1 ^ s2_2 ^ s3_3;
      s[3] = s0_3 ^ s1_1 ^ s2_1 ^ s3_2;
    }
}


////
//// AddRoundKey
////

static void AddRoundKey (huge state, int round)
{
  // ulong* s = (ulong*)state;
  // ulong* v = &w[4*round];
  huge s = (huge)state;
  huge v = &w[4*round];
  int row;
  for (row=0; row<4; row++)
    {
      s[row] ^= v[row];
    }
}


////
//// KeyExpansion
////

static void KeyExpansion (huge k)
{
  ulong temp;
  int i;
  for (i=0; i<Nk; i++)
    {
      w[i] = k[i];
    }
  for (i=Nk; i<(Nb*(Nr+1)); i++)
    {
      temp = w[i-1];
      if (i % Nk == 0)
	{
	  temp = RotWord (temp);
	  temp = SubWord (temp);
	  temp = temp ^ Rcon[i/Nk];
	}
      w[i] = w[i-Nk];
      w[i] = w[i] ^ temp;
    }
}


////
//// Cipher
////

static void Cipher (huge state)
{
  // Build the local variables.
  huge k_sch =  w;
  int round = 0;

  // First round.
  AddRoundKey (state, round);

  // Rounds 1 to Nr-1.
  for (k_sch+=4, round=1; round<Nr; k_sch+=4, round++)
    {
      SubBytes (state);
      ShiftRows (state);
      MixColumns (state);
      AddRoundKey (state, round);
    }

  // Last round.
  SubBytes (state);
  ShiftRows (state);
  AddRoundKey (state, round);
}



/******************************************************************************/


/*
\verb+int aes128_expand+\\
Implements the Key Expansion algorithm specified in FIPS 197 section 5.3 for $Nk=4$.
huge xk is a pointer to an external 128-bit unsigned integer, the key.
huge xw is a pointer to an external 44-element array of 32-bit unsigned integers, the schedule.
A 32-bit unsigned integer error code is returned.
*/

int aes_128_expand (huge xk, huge xw)
{
  w = xw;
  KeyExpansion (xk);
  return 0;
}


/*
\verb+int aes128_cipher+\\
Implements the Cipher algorithm specified in FIPS-197 section 5.1 for $Nk=4$.
huge c is a pointer to a 4-element array of 32-bit unsigned integers, the ciphertext.
huge p is a pointer to a 4-element array of 32-bit unsigned integers, the plaintext.
A 32-bit unsigned integer error code is returned.
*/

int aes_128_cipher (huge c, huge p)
{
  ulong state[4]; // the state register

  // Copy p1 into state.
  state[0] = p[0];
  state[1] = p[1];
  state[2] = p[2];
  state[3] = p[3];

  // Compute AES-128 cipher.
  Cipher(state);

  // Copy state into c.
  c[0] = state[0];
  c[1] = state[1];
  c[2] = state[2];
  c[3] = state[3];

  // Return no errors.
  return 0;
}


/*
\verb+int aes_128_cfbe+\\
Implements the AES-128 Cipher Feed-Back Encoder function.  It calls \verb+aes128_cipher+,
performs an exclusive-OR operation, and copies the new ciphertext to the feedback register.
huge c1 is a pointer to a 4-element array of 32-bit unsigned integers, the new ciphertext.
huge p1 is a pointer to a 4-element array of 32-bit unsigned integers, the new plaintext.
huge c0 is a pointer to a 4-element array of 32-bit unsigned integers, the old ciphertext.
A 32-bit unsigned integer error code is returned.
*/

int aes_128_cfbe (huge c1, huge p1, huge c0)
{
  ulong state[4]; // the state register

  // Move c0 into state.
  state[0] = c0[0];
  state[1] = c0[1];
  state[2] = c0[2];
  state[3] = c0[3];

  // Compute AES-128 cipher.
  Cipher(state);

  // Compute c1 = p1 xor state.
  c1[0] = p1[0] ^ state[0];
  c1[1] = p1[1] ^ state[1];
  c1[2] = p1[2] ^ state[2];
  c1[3] = p1[3] ^ state[3];

  // Copy c1 to c0, the feedback register.
  c0[0] = c1[0];
  c0[1] = c1[1];
  c0[2] = c1[2];
  c0[3] = c1[3];

  // Return no errors.
  return 0;
}


/*
\verb+aes_128_cfbd+\\
Implements the AES-128 Cipher Feed-Back Decoder function.  It calls \verb+aes_128_cipher+,
performs an exclusive-OR operation, and copies the new ciphertext to the feedback register.
huge p1 is a pointer to a 4-element array of 32-bit unsigned integers, the new plaintext.
huge c1 is a pointer to a 4-element array of 32-bit unsigned integers, the new ciphertext.
huge c0 is a pointer to a 4-element array of 32-bit unsigned integers, the old ciphertext.
A 32-bit unsigned integer error code is returned.
*/

int aes_128_cfbd (huge p1, huge c1, huge c0)
{
  int j;
  ulong state[4]; // the state register

  // Move c0 into state.
  state[0] = c0[0];
  state[1] = c0[1];
  state[2] = c0[2];
  state[3] = c0[3];

  // Compute AES-128 cipher.
  Cipher(state);

  // Compute p1 = c1 xor state.
  p1[0] = c1[0] ^ state[0];
  p1[1] = c1[1] ^ state[1];
  p1[2] = c1[2] ^ state[2];
  p1[3] = c1[3] ^ state[3];

  // Copy c1 to c0, the feedback register.
  c0[0] = c1[0];
  c0[1] = c1[1];
  c0[2] = c1[2];
  c0[3] = c1[3];

  // Return no errors.
  return 0;
}

