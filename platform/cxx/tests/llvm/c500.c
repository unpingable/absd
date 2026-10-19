#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct s0 { int a; long b; char n[16]; };
static int f0(struct s0 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1000) acc -= 7; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s1 { int a; long b; char n[16]; };
static int f1(struct s1 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1001) acc -= 8; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s2 { int a; long b; char n[16]; };
static int f2(struct s2 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1002) acc -= 9; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s3 { int a; long b; char n[16]; };
static int f3(struct s3 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1003) acc -= 10; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s4 { int a; long b; char n[16]; };
static int f4(struct s4 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1004) acc -= 11; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s5 { int a; long b; char n[16]; };
static int f5(struct s5 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1005) acc -= 12; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s6 { int a; long b; char n[16]; };
static int f6(struct s6 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1006) acc -= 13; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s7 { int a; long b; char n[16]; };
static int f7(struct s7 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1007) acc -= 14; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s8 { int a; long b; char n[16]; };
static int f8(struct s8 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1008) acc -= 15; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s9 { int a; long b; char n[16]; };
static int f9(struct s9 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1009) acc -= 16; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s10 { int a; long b; char n[16]; };
static int f10(struct s10 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1010) acc -= 17; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s11 { int a; long b; char n[16]; };
static int f11(struct s11 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1011) acc -= 18; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s12 { int a; long b; char n[16]; };
static int f12(struct s12 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1012) acc -= 19; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s13 { int a; long b; char n[16]; };
static int f13(struct s13 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1013) acc -= 20; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s14 { int a; long b; char n[16]; };
static int f14(struct s14 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1014) acc -= 21; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s15 { int a; long b; char n[16]; };
static int f15(struct s15 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1015) acc -= 22; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s16 { int a; long b; char n[16]; };
static int f16(struct s16 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1016) acc -= 23; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s17 { int a; long b; char n[16]; };
static int f17(struct s17 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1017) acc -= 24; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s18 { int a; long b; char n[16]; };
static int f18(struct s18 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1018) acc -= 25; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s19 { int a; long b; char n[16]; };
static int f19(struct s19 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1019) acc -= 26; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s20 { int a; long b; char n[16]; };
static int f20(struct s20 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1020) acc -= 27; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s21 { int a; long b; char n[16]; };
static int f21(struct s21 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1021) acc -= 28; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s22 { int a; long b; char n[16]; };
static int f22(struct s22 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1022) acc -= 29; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s23 { int a; long b; char n[16]; };
static int f23(struct s23 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1023) acc -= 30; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s24 { int a; long b; char n[16]; };
static int f24(struct s24 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1024) acc -= 31; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s25 { int a; long b; char n[16]; };
static int f25(struct s25 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1025) acc -= 32; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s26 { int a; long b; char n[16]; };
static int f26(struct s26 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1026) acc -= 33; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s27 { int a; long b; char n[16]; };
static int f27(struct s27 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1027) acc -= 34; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s28 { int a; long b; char n[16]; };
static int f28(struct s28 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1028) acc -= 35; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s29 { int a; long b; char n[16]; };
static int f29(struct s29 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1029) acc -= 36; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s30 { int a; long b; char n[16]; };
static int f30(struct s30 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1030) acc -= 37; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s31 { int a; long b; char n[16]; };
static int f31(struct s31 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1031) acc -= 38; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s32 { int a; long b; char n[16]; };
static int f32(struct s32 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1032) acc -= 39; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s33 { int a; long b; char n[16]; };
static int f33(struct s33 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1033) acc -= 40; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s34 { int a; long b; char n[16]; };
static int f34(struct s34 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1034) acc -= 41; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s35 { int a; long b; char n[16]; };
static int f35(struct s35 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1035) acc -= 42; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s36 { int a; long b; char n[16]; };
static int f36(struct s36 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1036) acc -= 43; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s37 { int a; long b; char n[16]; };
static int f37(struct s37 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1037) acc -= 44; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s38 { int a; long b; char n[16]; };
static int f38(struct s38 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1038) acc -= 45; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s39 { int a; long b; char n[16]; };
static int f39(struct s39 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1039) acc -= 46; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s40 { int a; long b; char n[16]; };
static int f40(struct s40 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1040) acc -= 47; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s41 { int a; long b; char n[16]; };
static int f41(struct s41 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1041) acc -= 48; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s42 { int a; long b; char n[16]; };
static int f42(struct s42 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1042) acc -= 49; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s43 { int a; long b; char n[16]; };
static int f43(struct s43 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1043) acc -= 50; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s44 { int a; long b; char n[16]; };
static int f44(struct s44 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1044) acc -= 51; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s45 { int a; long b; char n[16]; };
static int f45(struct s45 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1045) acc -= 52; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s46 { int a; long b; char n[16]; };
static int f46(struct s46 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1046) acc -= 53; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s47 { int a; long b; char n[16]; };
static int f47(struct s47 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1047) acc -= 54; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s48 { int a; long b; char n[16]; };
static int f48(struct s48 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1048) acc -= 55; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s49 { int a; long b; char n[16]; };
static int f49(struct s49 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1049) acc -= 56; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s50 { int a; long b; char n[16]; };
static int f50(struct s50 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1050) acc -= 57; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s51 { int a; long b; char n[16]; };
static int f51(struct s51 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1051) acc -= 58; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s52 { int a; long b; char n[16]; };
static int f52(struct s52 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1052) acc -= 59; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s53 { int a; long b; char n[16]; };
static int f53(struct s53 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1053) acc -= 60; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s54 { int a; long b; char n[16]; };
static int f54(struct s54 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1054) acc -= 61; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s55 { int a; long b; char n[16]; };
static int f55(struct s55 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1055) acc -= 62; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s56 { int a; long b; char n[16]; };
static int f56(struct s56 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1056) acc -= 63; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s57 { int a; long b; char n[16]; };
static int f57(struct s57 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1057) acc -= 64; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s58 { int a; long b; char n[16]; };
static int f58(struct s58 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1058) acc -= 65; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s59 { int a; long b; char n[16]; };
static int f59(struct s59 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1059) acc -= 66; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s60 { int a; long b; char n[16]; };
static int f60(struct s60 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1060) acc -= 67; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s61 { int a; long b; char n[16]; };
static int f61(struct s61 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1061) acc -= 68; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s62 { int a; long b; char n[16]; };
static int f62(struct s62 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1062) acc -= 69; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s63 { int a; long b; char n[16]; };
static int f63(struct s63 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1063) acc -= 70; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s64 { int a; long b; char n[16]; };
static int f64(struct s64 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1064) acc -= 71; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s65 { int a; long b; char n[16]; };
static int f65(struct s65 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1065) acc -= 72; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s66 { int a; long b; char n[16]; };
static int f66(struct s66 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1066) acc -= 73; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s67 { int a; long b; char n[16]; };
static int f67(struct s67 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1067) acc -= 74; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s68 { int a; long b; char n[16]; };
static int f68(struct s68 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1068) acc -= 75; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s69 { int a; long b; char n[16]; };
static int f69(struct s69 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1069) acc -= 76; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s70 { int a; long b; char n[16]; };
static int f70(struct s70 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1070) acc -= 77; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s71 { int a; long b; char n[16]; };
static int f71(struct s71 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1071) acc -= 78; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s72 { int a; long b; char n[16]; };
static int f72(struct s72 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1072) acc -= 79; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s73 { int a; long b; char n[16]; };
static int f73(struct s73 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1073) acc -= 80; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s74 { int a; long b; char n[16]; };
static int f74(struct s74 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1074) acc -= 81; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s75 { int a; long b; char n[16]; };
static int f75(struct s75 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1075) acc -= 82; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s76 { int a; long b; char n[16]; };
static int f76(struct s76 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1076) acc -= 83; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s77 { int a; long b; char n[16]; };
static int f77(struct s77 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1077) acc -= 84; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s78 { int a; long b; char n[16]; };
static int f78(struct s78 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1078) acc -= 85; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s79 { int a; long b; char n[16]; };
static int f79(struct s79 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1079) acc -= 86; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s80 { int a; long b; char n[16]; };
static int f80(struct s80 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1080) acc -= 87; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
struct s81 { int a; long b; char n[16]; };
static int f81(struct s81 *p, int k) {
  int acc = 0; for (int j = 0; j < k; j++) { acc += p->a * j + (int)p->b; if (acc > 1081) acc -= 88; }
  snprintf(p->n, sizeof p->n, "%d", acc); return acc + (int)strlen(p->n);
}
int main(int argc, char **argv) {
  long t = 0; (void)argv;
  { struct s0 v = {argc, 0, {0}}; t += f0(&v, argc + 0); }
  { struct s1 v = {argc, 1, {0}}; t += f1(&v, argc + 1); }
  { struct s2 v = {argc, 2, {0}}; t += f2(&v, argc + 2); }
  { struct s3 v = {argc, 3, {0}}; t += f3(&v, argc + 3); }
  { struct s4 v = {argc, 4, {0}}; t += f4(&v, argc + 4); }
  { struct s5 v = {argc, 5, {0}}; t += f5(&v, argc + 5); }
  { struct s6 v = {argc, 6, {0}}; t += f6(&v, argc + 6); }
  { struct s7 v = {argc, 7, {0}}; t += f7(&v, argc + 7); }
  { struct s8 v = {argc, 8, {0}}; t += f8(&v, argc + 8); }
  { struct s9 v = {argc, 9, {0}}; t += f9(&v, argc + 9); }
  { struct s10 v = {argc, 10, {0}}; t += f10(&v, argc + 10); }
  { struct s11 v = {argc, 11, {0}}; t += f11(&v, argc + 11); }
  { struct s12 v = {argc, 12, {0}}; t += f12(&v, argc + 12); }
  { struct s13 v = {argc, 13, {0}}; t += f13(&v, argc + 0); }
  { struct s14 v = {argc, 14, {0}}; t += f14(&v, argc + 1); }
  { struct s15 v = {argc, 15, {0}}; t += f15(&v, argc + 2); }
  { struct s16 v = {argc, 16, {0}}; t += f16(&v, argc + 3); }
  { struct s17 v = {argc, 17, {0}}; t += f17(&v, argc + 4); }
  { struct s18 v = {argc, 18, {0}}; t += f18(&v, argc + 5); }
  { struct s19 v = {argc, 19, {0}}; t += f19(&v, argc + 6); }
  { struct s20 v = {argc, 20, {0}}; t += f20(&v, argc + 7); }
  { struct s21 v = {argc, 21, {0}}; t += f21(&v, argc + 8); }
  { struct s22 v = {argc, 22, {0}}; t += f22(&v, argc + 9); }
  { struct s23 v = {argc, 23, {0}}; t += f23(&v, argc + 10); }
  { struct s24 v = {argc, 24, {0}}; t += f24(&v, argc + 11); }
  { struct s25 v = {argc, 25, {0}}; t += f25(&v, argc + 12); }
  { struct s26 v = {argc, 26, {0}}; t += f26(&v, argc + 0); }
  { struct s27 v = {argc, 27, {0}}; t += f27(&v, argc + 1); }
  { struct s28 v = {argc, 28, {0}}; t += f28(&v, argc + 2); }
  { struct s29 v = {argc, 29, {0}}; t += f29(&v, argc + 3); }
  { struct s30 v = {argc, 30, {0}}; t += f30(&v, argc + 4); }
  { struct s31 v = {argc, 31, {0}}; t += f31(&v, argc + 5); }
  { struct s32 v = {argc, 32, {0}}; t += f32(&v, argc + 6); }
  { struct s33 v = {argc, 33, {0}}; t += f33(&v, argc + 7); }
  { struct s34 v = {argc, 34, {0}}; t += f34(&v, argc + 8); }
  { struct s35 v = {argc, 35, {0}}; t += f35(&v, argc + 9); }
  { struct s36 v = {argc, 36, {0}}; t += f36(&v, argc + 10); }
  { struct s37 v = {argc, 37, {0}}; t += f37(&v, argc + 11); }
  { struct s38 v = {argc, 38, {0}}; t += f38(&v, argc + 12); }
  { struct s39 v = {argc, 39, {0}}; t += f39(&v, argc + 0); }
  { struct s40 v = {argc, 40, {0}}; t += f40(&v, argc + 1); }
  { struct s41 v = {argc, 41, {0}}; t += f41(&v, argc + 2); }
  { struct s42 v = {argc, 42, {0}}; t += f42(&v, argc + 3); }
  { struct s43 v = {argc, 43, {0}}; t += f43(&v, argc + 4); }
  { struct s44 v = {argc, 44, {0}}; t += f44(&v, argc + 5); }
  { struct s45 v = {argc, 45, {0}}; t += f45(&v, argc + 6); }
  { struct s46 v = {argc, 46, {0}}; t += f46(&v, argc + 7); }
  { struct s47 v = {argc, 47, {0}}; t += f47(&v, argc + 8); }
  { struct s48 v = {argc, 48, {0}}; t += f48(&v, argc + 9); }
  { struct s49 v = {argc, 49, {0}}; t += f49(&v, argc + 10); }
  { struct s50 v = {argc, 50, {0}}; t += f50(&v, argc + 11); }
  { struct s51 v = {argc, 51, {0}}; t += f51(&v, argc + 12); }
  { struct s52 v = {argc, 52, {0}}; t += f52(&v, argc + 0); }
  { struct s53 v = {argc, 53, {0}}; t += f53(&v, argc + 1); }
  { struct s54 v = {argc, 54, {0}}; t += f54(&v, argc + 2); }
  { struct s55 v = {argc, 55, {0}}; t += f55(&v, argc + 3); }
  { struct s56 v = {argc, 56, {0}}; t += f56(&v, argc + 4); }
  { struct s57 v = {argc, 57, {0}}; t += f57(&v, argc + 5); }
  { struct s58 v = {argc, 58, {0}}; t += f58(&v, argc + 6); }
  { struct s59 v = {argc, 59, {0}}; t += f59(&v, argc + 7); }
  { struct s60 v = {argc, 60, {0}}; t += f60(&v, argc + 8); }
  { struct s61 v = {argc, 61, {0}}; t += f61(&v, argc + 9); }
  { struct s62 v = {argc, 62, {0}}; t += f62(&v, argc + 10); }
  { struct s63 v = {argc, 63, {0}}; t += f63(&v, argc + 11); }
  { struct s64 v = {argc, 64, {0}}; t += f64(&v, argc + 12); }
  { struct s65 v = {argc, 65, {0}}; t += f65(&v, argc + 0); }
  { struct s66 v = {argc, 66, {0}}; t += f66(&v, argc + 1); }
  { struct s67 v = {argc, 67, {0}}; t += f67(&v, argc + 2); }
  { struct s68 v = {argc, 68, {0}}; t += f68(&v, argc + 3); }
  { struct s69 v = {argc, 69, {0}}; t += f69(&v, argc + 4); }
  { struct s70 v = {argc, 70, {0}}; t += f70(&v, argc + 5); }
  { struct s71 v = {argc, 71, {0}}; t += f71(&v, argc + 6); }
  { struct s72 v = {argc, 72, {0}}; t += f72(&v, argc + 7); }
  { struct s73 v = {argc, 73, {0}}; t += f73(&v, argc + 8); }
  { struct s74 v = {argc, 74, {0}}; t += f74(&v, argc + 9); }
  { struct s75 v = {argc, 75, {0}}; t += f75(&v, argc + 10); }
  { struct s76 v = {argc, 76, {0}}; t += f76(&v, argc + 11); }
  { struct s77 v = {argc, 77, {0}}; t += f77(&v, argc + 12); }
  { struct s78 v = {argc, 78, {0}}; t += f78(&v, argc + 0); }
  { struct s79 v = {argc, 79, {0}}; t += f79(&v, argc + 1); }
  { struct s80 v = {argc, 80, {0}}; t += f80(&v, argc + 2); }
  { struct s81 v = {argc, 81, {0}}; t += f81(&v, argc + 3); }
  printf("%ld\n", t); return (int)(t & 1);
}
