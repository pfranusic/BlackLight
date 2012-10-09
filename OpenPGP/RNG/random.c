// random.c

#include "stdlib.h"

int true_random_32 (unsigned long* n)
{
  *n = arc4random ();
  return 0;
}

