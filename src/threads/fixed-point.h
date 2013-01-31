/* FIXME: file header */

#define FRACTION_BITS 14

static typedef struct {
  int impl_value;
} fixed_point;

fixed_point fixed_point_create (int n);
int fixed_point_truncate (fixed_point x);
int fixed_point_round (fixed_point x);

fixed_point fixed_point_add (fixed_point x, fixed_point y);
fixed_point fixed_point_add_int (fixed_point x, int n);
fixed_point fixed_point_subtract (fixed_point x, fixed_point y);
fixed_point fixed_point_subtract_int (fixed_point x, int n);

fixed_point fixed_point_multiply (fixed_point x, fixed_point y);
fixed_point fixed_point_multiply_int (fixed_point x, int n);
fixed_point fixed_point_divide (fixed_point x, fixed_point y);
fixed_point fixed_point_divide_int (fixed_point x, int n);

/* FIXME: style? */
static inline fixed_point
_fixed_point_from_value (int impl_value) {
  fixed_point x = { impl_value };
  return x;
}   


static inline fixed_point 
fixed_point_create (int n) {
  return _fixed_point_from_value (n << FRACTION_BITS);
}

static inline int 
fixed_point_truncate (fixed_point x) {
  return x.impl_value >> FRACTION_BITS;
}

#define ONE_HALF (1 << (FRACTION_BITS - 1))
static inline int 
fixed_point_round (fixed_point x) {
  // FIXME: brace style?
  if (x.impl_value < 0) {
    return (x.impl_value - ONE_HALF) >> FRACTION_BITS;
  } else {
    return (x.impl_value + ONE_HALF) >> FRACTION_BITS;
  }
}

static inline fixed_point 
fixed_point_add (fixed_point x, fixed_point y) {
  return _fixed_point_from_value (x.impl_value + y.impl_value);
}

static inline fixed_point 
fixed_point_subtract (fixed_point x, fixed_point y) {
  return _fixed_point_from_value (x.impl_value - y.impl_value);
}

static inline fixed_point 
fixed_point_add_int (fixed_point x, int n) {
  return _fixed_point_from_value (x.impl_value + (n << FRACTION_BITS));
}

static inline fixed_point 
fixed_point_subtract_int (fixed_point x, int n) {
  return _fixed_point_from_value (x.impl_value - (n << FRACTION_BITS));
}

static inline fixed_point 
fixed_point_multiply (fixed_point x, fixed_point y) {
  int64_t val = (((int64_t) x.impl_value) * y.impl_value) >> FRACTION_BITS;
  return _fixed_point_from_value ((int) val);
}

static inline fixed_point 
fixed_point_multiply_int (fixed_point x, int n) {
  return _fixed_point_from_value (x.impl_value * n);
}

static inline fixed_point 
fixed_point_divide (fixed_point x, fixed_point y) {
  int64_t val = (((int64_t) x.impl_value) << FRACTION_BITS) / y.impl_value;
  return _fixed_point_from_value ((int) val);
}

static inline fixed_point 
fixed_point_divide_int (fixed_point x, int n) {
  return _fixed_point_from_value (x.impl_value / n);
}


