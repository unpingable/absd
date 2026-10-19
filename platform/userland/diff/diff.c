/* Bounded ABSD adaptation of Toybox 0.8.15 toys/pending/diff.c.
 * Copyright 2014 Sandeep Sharma <sandeep.jack2756@gmail.com>
 * Copyright 2014 Ashwini Kumar <ak.ashwini1981@gmail.com>
 * See LICENSE and README.md for provenance and bounded interface.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef DIFF_MAX_BYTES
#define DIFF_MAX_BYTES 65536
#endif
#ifndef DIFF_MAX_LINES
#define DIFF_MAX_LINES 1024
#endif
#ifndef DIFF_MAX_CANDIDATES
#define DIFF_MAX_CANDIDATES 65536
#endif
#ifndef DIFF_MAX_WORK
#define DIFF_MAX_WORK 1000000
#endif
#ifndef DIFF_MAX_ALLOC
#define DIFF_MAX_ALLOC 4194304
#endif
#define minof(a,b) ((a)<(b)?(a):(b))
#define maxof(a,b) ((a)>(b)?(a):(b))
static size_t allocated, candidates, work;
static void fail(const char *why) { fprintf(stderr, "diff: %s\n", why); exit(2); }
static void step(void) { if (work++ >= DIFF_MAX_WORK) fail("work limit"); }
static void *xrealloc(void *old, size_t n) {
  if (n > DIFF_MAX_ALLOC || allocated > DIFF_MAX_ALLOC-n) fail("allocation limit");
  allocated += n;
  void *p = realloc(old, n);
  if (!p) fail("allocation failure");
  return p;
}
static void *xzalloc(size_t n) { void *p=xrealloc(NULL,n); memset(p,0,n); return p; }
/* Capture each input once. This is a bounded byte sequence, not a claim of an
 * atomic filesystem snapshot under concurrent writes. No reread of mutable
 * pathname contents can change hashing, verification or rendering. */
struct input { unsigned char *data; size_t size, pos; };
static int getbyte(struct input *in) {
  return in->pos == in->size ? EOF : in->data[in->pos++];
}
static void seekbyte(struct input *in, size_t pos) {
  if (pos > in->size) fail("invalid captured offset");
  in->pos=pos;
}
static struct {
  long U;
  int differ, *offset[2];
  struct { struct input *fp; int len; } file[2];
} TT;
struct v_vector {
  unsigned serial:31;
  unsigned last:1;
  union {
    unsigned hash;
    unsigned p;
  };
};

struct diff {
  long a, b, c, d, prev, suff;
};

struct candidate {
  struct candidate *next, *prev;
  int a, b;
};

enum {
  empty = 1 << 9,
  eol = 1 << 10,
  eof = 1 << 11,
  space = 1 << 12
};

static int comp(const void *a, const void *b)
{
  const struct v_vector *l=a, *r=b;
  if (l->hash != r->hash) return l->hash < r->hash ? -1 : 1;
  return (l->serial > r->serial) - (l->serial < r->serial);
}

static int search(struct candidate **K, int r, int k, int j)
{
  int low = r, upper = k, mid;

  while (low<=(mid = (low+upper)/2)) {
    step();
    if (K[mid]->b < j && K[mid + 1]->b > j) return mid;
    if (K[mid]->b < j) low = mid + 1;
    else if (K[mid]->b > j) upper = mid - 1;
    else return -1;
  }
  return -1;
}

static struct candidate *new_candidate(int i, int j, struct candidate *prev)
{
  if (candidates++ >= DIFF_MAX_CANDIDATES) fail("candidate limit");
  struct candidate *c = xzalloc(sizeof(struct candidate));

  c->a = i;
  c->b = j;
  c->prev = prev;
  return c;
}

/* 1. Search K[r: k] for an element K[s] such that K[s]-> b < j and K[s + 1]->b > j
 * 2. if found do
 *  2.a. If K[s + 1]->b > j do K[r] = c; r = s+1 and c = candidate(i, j, K[s]) //we have a candidate
 *  2.b. if s = k (fence reached move it further) do K[k + 2] = K[k + 1], k++
 * 3. if E[p].last true break i.e we have reached at the end of an equiv class
 *    else p = p + 1 //keep traversing the equiv class.
 * 4. K[r] = c //Save the sucessfully filled k-candidate.
 */
static void do_merge(struct candidate **K, int *k, int i,
    struct v_vector *E, int p)
{
  int r = 0, s, j;
  struct candidate *pr = 0, *c = K[0];

  for (;;) {
    step();
    j = E[p].serial;
    s = search(K, r, *k, j);
    if (s>=0 && K[s]->b<j && K[s+1]->b>j) {
      if (K[s+1]->b>j) {
        pr = K[s];
        if (r && K[r]) c->next = K[r];
        K[r] = c;
        r = s+1;
        c = new_candidate(i , j, pr);
      }
      if (s == *k) {
        ++*k;
        K[*k+1] = K[*k];
        break;
      }
    }
    if (E[p].last) break;
    else p++;
  }
  K[r] = c;
}

static int read_tok(struct input *fp, off_t *off, int tok)
{
  tok |= empty;
  if (!(tok & eol)) {
    int t=getbyte(fp);
    if (off && t != EOF) ++*off;
    tok |= (t & (eof + eol));
    if (t == '\n') tok |= eol;
    tok &= ~(empty + 0xff);
    tok |= t;
  }
  return tok;
}

static int bcomp(const void *a, const void *b)
{
  const struct v_vector *l=a, *r=b;
  if (l->hash != r->hash) return l->hash < r->hash ? -1 : 1;
  return r[-1].last ? 0 : -1;
}

/*  file[0] corresponds file 1 and file[1] correspond file 2.
 * 1. calc hashes for both the files and store them in vector(v[0], v[1])
 * 2. sort file[1] with hash as primary and serial as sec. key
 * 3. Form the equivalance class of file[1] stored in e vector. It lists all the equivalence
 *    classes of lines in file[1], with e.last = true on the last element of each class.
 *    The elements are ordered by serial within classes.
 * 4. Form the p vector stored in  p_vector. p_vector[i], if non-zero, now points in e vector
 *    to the beginning of the equiv class of lines in file[1] equivalent to line
 *    i in file[0].
 * 5. Form the k-candidates as discribed in do_merge.
 * 6. Create a vector J[i] = j, such that i'th line in file[0] is j'th line of
 *    file[1], i.e J comprises LCS
 */
static int *create_j_vector()
{
  int tok, i, j, size = DIFF_MAX_LINES+3, k;
  off_t off;
  uint32_t hash;
  int *p_vector, *J;
  struct v_vector *v[2], *e;
  struct candidate **kcand, *pr;

  for (i = 0; i < 2; i++) {
    tok = off = 0;
    hash = 5831;
    v[i] = xzalloc(size * sizeof(struct v_vector));
    TT.offset[i] = xzalloc(size * sizeof(int));
    TT.file[i].len = 0;
    seekbyte(TT.file[i].fp, 0);

    while (1) {
      tok  = read_tok(TT.file[i].fp, &off, tok);
      if (!(tok & empty)) {
        hash = ((hash << 5) + hash) + (tok & 0xff);
        continue;
      }

      if (++TT.file[i].len >= size) fail("line limit");

      v[i][TT.file[i].len].hash = hash & INT_MAX;
      TT.offset[i][TT.file[i].len] = off;
      if ((tok & eof)) {
        TT.offset[i][TT.file[i].len] = ++off;
        break;
      }
      hash = 5831;  //next line
      tok = 0;
    }
    if (TT.offset[i][TT.file[i].len]-TT.offset[i][TT.file[i].len-1] == 1)
      TT.file[i].len--;
  }

  for (i = 0; i<=TT.file[1].len; i++) v[1][i].serial = i;
  qsort(v[1]+1, TT.file[1].len, sizeof(struct v_vector), comp);

  e = v[1];
  e[0].serial = 0;
  e[0].last = 1;
  for (i = 1; i<=TT.file[1].len; i++)
    e[i].last = i==TT.file[1].len || v[1][i].hash!=v[1][i+1].hash;

  p_vector = xzalloc((TT.file[0].len+2)*sizeof(int));
  for (i = 1; i<=TT.file[0].len; i++) {
    void *r = bsearch(&v[0][i], e+1, TT.file[1].len, sizeof(*e), bcomp);
    if (r) p_vector[i] = (struct v_vector *)r - e;
  }

  for (i = 1; i<=TT.file[0].len; i++) e[i].p = p_vector[i];
  free(p_vector);

  size = DIFF_MAX_LINES+3;
  kcand = xzalloc(size * sizeof(struct candidate *));

  kcand[0] = new_candidate(0 , 0, 0);
  kcand[1] = new_candidate(TT.file[0].len+1, TT.file[1].len+1, 0); //the fence

  k = 0;  //last successfully filled k candidate.
  for (i = 1; i<=TT.file[0].len; i++) {
    if (!e[i].p) continue;
    do_merge(kcand, &k, i, e, e[i].p);
  }
  free(v[0]); //no need for v_vector now.
  free(v[1]);

  J = xzalloc((TT.file[0].len+2)*sizeof(int));

  for (pr = kcand[k]; pr; pr = pr->prev) J[pr->a] = pr->b;
  J[TT.file[0].len+1] = TT.file[1].len+1; //mark boundary

  for (i = k+1; i>=0; i--) {
    struct candidate *c=kcand[i];
    while (c) { struct candidate *next=c->next; free(c); c=next; }
  }
  free(kcand);

  for (i = 1; i<=TT.file[0].len; i++) { // jackpot?
    if (!J[i]) continue;

    seekbyte(TT.file[0].fp, TT.offset[0][i-1]);
    seekbyte(TT.file[1].fp, TT.offset[1][J[i]-1]);

    for (j = J[i]; i<=TT.file[0].len && J[i]==j; i++, j++) {
      int tok0 = 0, tok1 = 0;

      do {
        tok0 = read_tok(TT.file[0].fp, NULL, tok0);
        tok1 = read_tok(TT.file[1].fp, NULL, tok1);
        if (((tok0 ^ tok1) & empty) || ((tok0 & 0xff) != (tok1 & 0xff)))
          J[i] = 0;
      } while (!(tok0 & tok1 & empty));
    }
  }
  return J;
}

static void show_label(const char *prefix, const char *name)
{
  /* Always quote labels. Cast bytes before octal conversion; no signed-char
   * expansion and no pointer arithmetic on a null sizing buffer. */
  printf("%s \"",prefix);
  for (const unsigned char *p=(const unsigned char *)name; *p; ++p) {
    if (*p == '\\' || *p == '\"') { putchar('\\'); putchar(*p); }
    else if (*p < 32 || *p >= 127) printf("\\%03o",*p);
    else putchar(*p);
  }
  puts("\"");
}
static void print_diff(int a, int b, char c, int *offset, struct input *fp)
{
  for (int i=a; i<=b; ++i) {
    seekbyte(fp,offset[i-1]);
    putchar(c);
    for (int j=0; j<offset[i]-offset[i-1]; ++j) {
      int cc=getbyte(fp);
      if (cc == EOF) { printf("\n\\ No newline at end of file\n"); return; }
      putchar(cc);
    }
  }
}
static void do_diff(char **files)
{
  long i = 1, size = 1, x = 0, change = 0,
   start1, end1, start2, end2;
  struct diff *d;
  int *J;

  TT.offset[0] = TT.offset[1] = NULL;
  J = create_j_vector();

  if (!J) return; //No need to compare, have to status only

  d = xzalloc(size *sizeof(struct diff));
  do {
    for (d[x].a = i; d[x].a<=TT.file[0].len; d[x].a++) {
      if (J[d[x].a] != (J[d[x].a - 1] + 1)) break;
      else continue;
    }
    d[x].c = (J[d[x].a - 1] + 1);

    for (d[x].b = (d[x].a - 1); d[x].b<=TT.file[0].len; d[x].b++) {
      if (J[d[x].b + 1]) break;
      else continue;
    }
    d[x].d = (J[d[x].b + 1] - 1);

    //is we have diff ?   TODO: lolcat?
    if ((d[x].a <= d[x].b || d[x].c <= d[x].d)) change = 1;

    d = xrealloc(d, (x + 2) *sizeof(struct diff));
    i = d[x].b + 1;
    if (i>TT.file[0].len) break;
    J[d[x].b] = d[x].d;
    x++;
  } while (i<=TT.file[0].len);

  i = x+1;
  TT.differ = change; //update status, may change bcoz of -w etc.

  if (change) {
    show_label("---", files[0]);
    show_label("+++", files[1]);

    struct diff *t, *ptr1 = d, *ptr2 = d;
    while (i) {
      long a;

      // trim context to file len.
      if (TT.U>TT.file[0].len) TT.U = TT.file[0].len;
      if (ptr1->b < ptr1->a && ptr1->d < ptr1->c) {
        i--;
        continue;
      }
      //Handle the context stuff
      a =  ptr1->a;
      if (i == x + 1) ptr1->suff = maxof(1, a-TT.U);
      else if (ptr1[-1].prev >= ptr1->a-TT.U) ptr1->suff = ptr1[-1].prev+1;
      else ptr1->suff =  ptr1->a-TT.U;
calc_ct:
      if (i > 1) {
        if ((ptr2->b + TT.U) >= (ptr2  + 1)->a) {
          ptr2++;
          i--;
          goto calc_ct;
        } else ptr2->prev = ptr2->b + TT.U;
      } else ptr2->prev = ptr2->b;
      start1 = (ptr2->prev - ptr1->suff + 1);
      end1 = (start1 == 1) ? -1 : start1;
      start2 = maxof(1, ptr1->c - (ptr1->a - ptr1->suff));
      end2 = ptr2->prev - ptr2->b + ptr2->d;

      {
        printf("@@ -%ld", start1 ? ptr1->suff: (ptr1->suff -1));
        if (end1 != -1) printf(",%ld ", ptr2->prev-ptr1->suff + 1);
        else putchar(' ');

        printf("+%ld", (end2 - start2 + 1) ? start2: (start2 -1));
        if ((end2 - start2 +1) != 1) printf(",%ld ", (end2 - start2 +1));
        else putchar(' ');
        printf("@@");
        putchar('\n');
      }

      for (t = ptr1; t <= ptr2; t++) {
        if (t==ptr1) print_diff(t->suff, t->a-1, ' ', TT.offset[0], TT.file[0].fp);
        print_diff(t->a, t->b, '-', TT.offset[0], TT.file[0].fp);
        print_diff(t->c, t->d, '+', TT.offset[1], TT.file[1].fp);
        if (t == ptr2)
          print_diff(t->b+1, (t)->prev, ' ', TT.offset[0], TT.file[0].fp);
        else print_diff(t->b+1, (t+1)->a-1, ' ', TT.offset[0], TT.file[0].fp);
      }
      ptr2++;
      ptr1 = ptr2;
      i--;
    } //end of while
  } //End of !FLAG_q
  free(d);
  free(J);
  free(TT.offset[0]);
  free(TT.offset[1]);
}

static void capture(const char *name, struct input *in)
{
  struct stat st;
  /* Precheck avoids opening ordinary FIFOs. Inputs and pathname bindings must
   * remain stable during open; no promise against concurrent FIFO substitution. */
  if (stat(name,&st) || !S_ISREG(st.st_mode)) fail("input must be a named regular file");
  FILE *fp=fopen(name,"rb");
  if (!fp) fail("open failed");
  if (fstat(fileno(fp),&st) || !S_ISREG(st.st_mode)) fail("opened input not regular");
  if (fseek(fp,0,SEEK_SET)) fail("seek failed");
  in->data=xzalloc(DIFF_MAX_BYTES+1);
  in->size=fread(in->data,1,DIFF_MAX_BYTES+1,fp);
  int bad=ferror(fp) || (in->size <= DIFF_MAX_BYTES && !feof(fp));
  if (fclose(fp)) bad=1;
  if (bad) fail("input read/close failed");
  if (in->size > DIFF_MAX_BYTES) fail("byte limit");
  size_t lines=0;
  for (size_t n=0;n<in->size;++n) if (in->data[n]=='\n') ++lines;
  if (in->size && in->data[in->size-1]!='\n') ++lines;
  if (lines > DIFF_MAX_LINES) fail("line limit");
}
int main(int argc, char **argv)
{
  int a=1;
  if (a<argc && !strcmp(argv[a],"-u")) ++a;
  if (a<argc && !strcmp(argv[a],"--")) ++a;
  else if (a<argc && argv[a][0]=='-') fail("usage: diff [-u] [--] file1 file2");
  if (argc-a!=2 || !strcmp(argv[a],"-") || !strcmp(argv[a+1],"-"))
    fail("usage: diff [-u] [--] file1 file2");
  struct input in[2]={{0}};
  capture(argv[a],in); capture(argv[a+1],in+1);
  TT.file[0].fp=in; TT.file[1].fp=in+1; TT.U=3;
  TT.differ=in[0].size!=in[1].size || memcmp(in[0].data,in[1].data,in[0].size);
  TT.differ=!!TT.differ;
  if (TT.differ) {
    if (memchr(in[0].data,0,in[0].size) || memchr(in[1].data,0,in[1].size)) {
      show_label("Binary files",argv[a]); show_label("and",argv[a+1]); puts("differ");
    } else do_diff(argv+a);
  }
  free(in[0].data); free(in[1].data);
  if (fflush(stdout) || ferror(stdout)) fail("output failed");
  return TT.differ;
}
