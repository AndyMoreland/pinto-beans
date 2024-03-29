/* fixed-point-inline.h: 
 * --------------------
 * Included as the definition of the 'fixed_point'
 * type and associated functions by "fixed-point.h"
 * when the FIXED_POINT_INLINE preprocessor variable
 * is defined.
 *
 * all associated functions are implemented directly 
 * as macros. Note that unlike the other implementation
 * of fixed-point, this one is _not_ type-safe with
 * respect to ints and fixed_points.
 */

#ifndef THREADS_FIXED_POINT_H 
#error "fixed-point-inline.h should only be included through fixed-point.h"
#endif

typedef int fixed_point;

#define ONE_HALF (1 << (FRACTION_BITS - 1))

#define _fp_left(n) ((n) << FRACTION_BITS)
#define _fp_right(n) ((n) >> FRACTION_BITS)

#define fixed_point_create(n) (_fp_left(n))
#define fixed_point_truncate(x) (_fp_right(x))
#define fixed_point_round(x) ((x)<0? _fp_right((x)-ONE_HALF) : _fp_right((x) + ONE_HALF))

#define fixed_point_add(x,y) ((x) + (y))
#define fixed_point_subtract(x,y) ((x) - (y))
#define fixed_point_add_int(x,n) ((x) + _fp_left(n))
#define fixed_point_subtract_int(x,n) ((x) - _fp_left(n)) 
#define fixed_point_multiply(x,y) ((fixed_point)(_fp_right(((int64_t)(x)) * (y))))
#define fixed_point_multiply_int(x,n) ((x) * (n))
#define fixed_point_divide(x,y) ((fixed_point)(_fp_left((int64_t)(x)) / (y)))
#define fixed_point_divide_int(x,n) ((x) / (n))
#define fixed_point_ratio(num,denom) (_fp_left(num) / (denom))

