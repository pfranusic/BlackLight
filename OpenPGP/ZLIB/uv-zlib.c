// uv-zlib.c
// Contains the two functions uv_deflate and uv_inflate.
// Both are called by Blacklight via the shared library libz.dylib
// and the Clozure Common Lisp Foreign Function Interface (CCL-FFI).
// uv_deflate calls deflateInit, deflate, and deflateEnd.
// uv_inflate calls inflateInit, inflate, and inflateEnd.
// Each function is able to process large messages by making 
// multiple calls to deflate or inflate.
// Copyright 2011 Peter Franusic

#define ZLIB_INTERNAL
#include "zlib.h"

/*********************************************************************
uv-deflate compresses the source buffer into the destination buffer.
sourceLen is the byte length of the source buffer.
Upon entry, destLen is the total size of the destination buffer, 
which must be at least 0.1% larger than sourceLen plus 12 bytes.
Upon exit, destLen is the actual size of the compressed buffer.

uv-deflate returns Z_OK if success,
Z_MEM_ERROR if there was not enough memory, 
Z_BUF_ERROR if there was not enough room in the output buffer,
Z_STREAM_ERROR if the level parameter is invalid.
*********************************************************************/

int ZEXPORT uv_deflate (dest, destLen, source, sourceLen)
     Bytef *dest;
     uLongf *destLen;
     const Bytef *source;
     uLong sourceLen;
{
  z_stream stream;
  int err;
  
  stream.next_in = (Bytef*)source;
  stream.avail_in = (uInt)sourceLen;

#ifdef MAXSEG_64K
  /* Check for source > 64K on 16-bit machine: */
  if ((uLong)stream.avail_in != sourceLen) return Z_BUF_ERROR;
#endif

  stream.next_out = dest;
  stream.avail_out = (uInt)*destLen;
  if ((uLong)stream.avail_out != *destLen) return Z_BUF_ERROR;
  
  stream.zalloc = (alloc_func)0;
  stream.zfree = (free_func)0;
  stream.opaque = (voidpf)0;
  
  err = deflateInit(&stream, Z_DEFAULT_COMPRESSION);
  if (err != Z_OK) return err;
  
  err = deflate(&stream, Z_FINISH);
  if (err != Z_STREAM_END)
    {
      deflateEnd(&stream);
      return err == Z_OK ? Z_BUF_ERROR : err;
    }
  *destLen = stream.total_out;
  
  err = deflateEnd(&stream);
  return err;
}


/*********************************************************************
uv_inflate decompresses the source buffer into the destination buffer.
sourceLen is the byte length of the source buffer.
Upon entry, destLen is the total size of the destination buffer, 
which must be large enough to hold the entire uncompressed data.
(The size of the uncompressed data must have been saved previously 
by the compressor and transmitted to the decompressor by some 
mechanism outside the scope of this compression library.)
Upon exit, destLen is the actual size of the compressed buffer.

uv_inflate returns Z_OK if success,
Z_MEM_ERROR if there was not enough memory,
Z_BUF_ERROR if there was not enough room in the output buffer, or 
Z_DATA_ERROR if the input data was corrupted.
*********************************************************************/

int ZEXPORT uv_inflate (dest, destLen, source, sourceLen)
     Bytef *dest;
     uLongf *destLen;
     const Bytef *source;
     uLong sourceLen;
{
  z_stream stream;
  int err;
  
  stream.next_in = (Bytef*)source;
  stream.avail_in = (uInt)sourceLen;

  /* Check for source > 64K on 16-bit machine: */
  if ((uLong)stream.avail_in != sourceLen) return Z_BUF_ERROR;
  
  stream.next_out = dest;
  stream.avail_out = (uInt)*destLen;
  if ((uLong)stream.avail_out != *destLen) return Z_BUF_ERROR;
  
  stream.zalloc = (alloc_func)0;
  stream.zfree = (free_func)0;
  
  err = inflateInit(&stream);
  if (err != Z_OK) return err;
  
  err = inflate(&stream, Z_FINISH);
  if (err != Z_STREAM_END)
    {
      inflateEnd(&stream);
      if (err == Z_NEED_DICT || (err == Z_BUF_ERROR && stream.avail_in == 0))
	return Z_DATA_ERROR;
      return err;
    }
  *destLen = stream.total_out;
  
  err = inflateEnd(&stream);
  return err;
}

