/* fixed-point.h: 
 * ----------------
 * Includes definition of the 'fixed_point' type
 * and associated fixed-point arithmetic operations.
 * The default implementation is type-safe with
 * respect to ints and fixed_points; that is, the
 * function signatures have enough type information
 * to warn about improper use of the API.
 *
 * If the FIXED_POINT_INLINE preprocessor variable
 * is defined, this default implemtantation will be
 * replaced in favor of a macro-only definition,
 * which dumps type safety in favor of guaranteed
 * function inlining. It is recommended to leave
 * FIXED_POINT_INLINE off during development.
 */

#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

/* The number of bits used to represent the fraction
 * component of a fixed_point. Increasing this will
 * add fraction precision but decrease maximum value.
 */
#define FRACTION_BITS 14

#ifdef FIXED_POINT_INLINE
#include "fixed-point-inline.h"
#else

/* Implement fixed_point as a struct
 * that wraps an int to prevent accidental
 * type-conversion to a raw 'int'. Use
 * fixed_point_create and fixed_point_truncate
 * (or fixed_point_round) to convert between
 * the fixed_point and int type.
 */
typedef struct
  { 
    int impl_value;
  } fixed_point;

/* Creates a fixed_point from the given 'int' value */
static inline fixed_point fixed_point_create (int n);
/* Creates a fixed_point equal to num / denom */
static inline fixed_point fixed_point_ratio (int num, int denom);

/* Converts a fixed_point back to an int by truncating the decimal */
static inline int fixed_point_truncate (fixed_point x);
/* Converts a fixed_point back to an int by rounding the decimal */
static inline int fixed_point_round (fixed_point x);

static inline fixed_point fixed_point_add (fixed_point x, fixed_point y);
static inline fixed_point fixed_point_add_int (fixed_point x, int n);
static inline fixed_point fixed_point_subtract (fixed_point x, fixed_point y);
static inline fixed_point fixed_point_subtract_int (fixed_point x, int n);

static inline fixed_point fixed_point_multiply (fixed_point x, fixed_point y);
static inline fixed_point fixed_point_multiply_int (fixed_point x, int n);
static inline fixed_point fixed_point_divide (fixed_point x, fixed_point y);
static inline fixed_point fixed_point_divide_int (fixed_point x, int n);

/*===== DEFAULT API IMPLEMENTATION =====*/

static inline fixed_point
_fixed_point_from_value (int impl_value)
{
  fixed_point x = { impl_value };
  return x;
}   


static inline fixed_point 
fixed_point_create (int n)
{
  return _fixed_point_from_value (n << FRACTION_BITS);
}

static inline int 
fixed_point_truncate (fixed_point x)
{
  return x.impl_value >> FRACTION_BITS;
}

#define ONE_HALF (1 << (FRACTION_BITS - 1))
static inline int 
fixed_point_round (fixed_point x)
{
  if (x.impl_value < 0)
    return (x.impl_value - ONE_HALF) >> FRACTION_BITS;
  else
    return (x.impl_value + ONE_HALF) >> FRACTION_BITS;
}

static inline fixed_point 
fixed_point_add (fixed_point x, fixed_point y)
{
  return _fixed_point_from_value (x.impl_value + y.impl_value);
}

static inline fixed_point 
fixed_point_subtract (fixed_point x, fixed_point y)
{
  return _fixed_point_from_value (x.impl_value - y.impl_value);
}

static inline fixed_point 
fixed_point_add_int (fixed_point x, int n)
{
  return _fixed_point_from_value (x.impl_value + (n << FRACTION_BITS));
}

static inline fixed_point 
fixed_point_subtract_int (fixed_point x, int n)
{
  return _fixed_point_from_value (x.impl_value - (n << FRACTION_BITS));
}

static inline fixed_point 
fixed_point_multiply (fixed_point x, fixed_point y)
{
  int64_t val = (((int64_t) x.impl_value) * y.impl_value) >> FRACTION_BITS;
  return _fixed_point_from_value ((int) val);
}

static inline fixed_point 
fixed_point_multiply_int (fixed_point x, int n)
{
  return _fixed_point_from_value (x.impl_value * n);
}

static inline fixed_point 
fixed_point_divide (fixed_point x, fixed_point y)
{
  int64_t val = (((int64_t) x.impl_value) << FRACTION_BITS) / y.impl_value;
  return _fixed_point_from_value ((int) val);
}

static inline fixed_point 
fixed_point_divide_int (fixed_point x, int n)
{
  return _fixed_point_from_value (x.impl_value / n);
}

static inline fixed_point
fixed_point_ratio (int num, int denom)
{
  return fixed_point_divide_int (fixed_point_create (num), denom);
}

#endif /* ifndef FIXED_POINT_INLINE */
#endif /* ifndef THREAD_FIXED_POINT_H */

