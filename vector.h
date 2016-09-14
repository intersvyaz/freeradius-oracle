#ifndef RLM_ORACLE_VECTOR_H
#define RLM_ORACLE_VECTOR_H

#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#ifndef oom
#define oom() exit(-1)
#endif

#define vec(type) struct {                                                 \
  size_t i;  /* i: index of next available slot,  */                          \
  size_t n;  /* n: num slots */                                               \
  type *d;   /* n slots of size icd->sz*/                                     \
}

#define vec_free(a) do {                                                   \
  if ((a).n) { free((a).d); }                                                 \
  memset(&(a), 0, sizeof(a));                                                 \
} while(0)

#define vec_reserve(a, by) do {                                            \
  if (((a).i + (by)) > (a).n) {                                               \
    void *vec_tmp;                                                         \
    while(((a).i + (by)) > (a).n) { (a).n = ((a).n ? (2 * (a).n) : 8); }    \
    vec_tmp = realloc((a).d, (a).n * sizeof(*(a).d));                      \
    if (vec_tmp == NULL) oom();                                            \
    (a).d = vec_tmp;                                                       \
  }                                                                           \
} while(0)

#define vec_push_back(a, p) do {                                           \
  vec_reserve(a, 1);                                                       \
  memcpy(_vec_eltptr(a, (a).i++), p, sizeof(*(a).d));                      \
} while(0)

#define vec_pop_back(a) do ({                                              \
  (a).i--;                                                                    \
  (a).d[(a).i];                                                               \
})

#define vec_extend_back(a) do ({                                           \
  vec_reserve(a, 1);                                                       \
  memset(_vec_eltptr(a, (a).i++), 0, sizeof(*(a).d);                       \
  (a).d[(a).i];                                                               \
})

#define vec_len(a) ((a).i)

#define vec_body(a) ((a).d)

#define vec_elt(a, j) ((a).d[(j)])

#define _vec_eltptr(a, j) (((a).d + (j)))

#define vec_insert(a, p, j) do {                                           \
  if (j > (a).i) vec_resize(a, j);                                         \
  vec_reserve(a, 1);                                                       \
  if ((j) < (a).i) {                                                          \
    memmove( _vec_eltptr(a, (j) + 1), _vec_eltptr(a, j), ((a).i - (j)) * sizeof(*(a).d)); \
  }                                                                           \
  memcpy(_vec_eltptr(a, j), p, sizeof(*(a).d));                            \
  (a).i++;                                                                    \
} while(0)

#define vec_inserta(a, w, j) do {                                          \
  if (vec_len(w) == 0) break;                                              \
  if ((j) > (a).i) vec_resize(a, j);                                       \
  vec_reserve(a, vec_len(w));                                           \
  if ((j) < (a).i) {                                                          \
    memmove(_vec_eltptr(a, (j) + vec_len(w)), _vec_eltptr(a, j),  ((a).i - (j)) * sizeof(*(a).d)); \
  }                                                                           \
  memcpy(_vec_eltptr(a, j), _vec_eltptr(w, 0), vec_len(w) * sizeof(*(a).d)); \
  (a).i += vec_len(w);                                                    \
} while(0)

#define vec_resize(a, num) do {                                            \
  if ((a).i < (num)) {                                                        \
    vec_reserve((a), (num) - (a).i);                                     \
    memset(_vec_eltptr((a), (a).i), 0, sizeof(*(a).d));                 \
  }                                                                           \
  (a).i = num;                                                               \
} while(0)

#define vec_concat(dst, src) do {                                          \
  vec_inserta((dst), (src), vec_len(dst));                              \
} while(0)

#define vec_erase(a, pos, len) do {                                        \
  if ((a).i > ((pos) + (len))) {                                              \
    memmove(_vec_eltptr((a), pos), _vec_eltptr((a), (pos) + (len)), ((a).i - (pos) - (len)) * sizeof(*(a).d)); \
  }                                                                           \
  (a).i -= (len);                                                             \
} while(0)

#define vec_clear(a) do {                                                 \
  (a).i = 0;                                                                 \
} while(0)

#define vec_sort(a, cmp) do {                                              \
  qsort((a).d, (a).i, sizeof(*(a).d), cmp);                                   \
} while(0)

#define vec_find(a, v, cmp) bsearch((v), (a).d, (a).i, sizeof(*(a).d))

#define vec_front(a) (((a).i) ? (_vec_eltptr(a, 0)) : NULL)
#define vec_back(a) (((a).i) ? (_vec_eltptr(a, (a).i - 1)) : NULL)

#endif // RLM_ORACLE_VECTOR_H
