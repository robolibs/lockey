#pragma once

// Ed25519 Digital Signatures (RFC 8032)
// Uses SHA-512 for hashing (required by RFC 8032)
// Adapted from Monocypher (BSD-2-Clause OR CC0-1.0)
// Original: Copyright (c) 2017-2020, Loup Vaillant
//
// This implementation MUST be bit-exact compatible with libsodium because
// signatures are transmitted over the wire in the verify protocol.

#include <cstddef>
#include <cstdint>

#include "keylock/crypto/constant_time/wipe.hpp"
#include "keylock/crypto/curve25519/common.hpp"
#include "keylock/crypto/curve25519/field.hpp"
#include "keylock/crypto/curve25519/scalar.hpp"
#include "keylock/crypto/rng/randombytes.hpp"
#include "keylock/hash/sha512/sha512.hpp"

namespace keylock::crypto::ed25519 {

    // Constants matching libsodium
    inline constexpr size_t PUBLICKEYBYTES = 32;
    inline constexpr size_t SECRETKEYBYTES = 64;
    inline constexpr size_t BYTES = 64; // signature size
    inline constexpr size_t SEEDBYTES = 32;

    namespace detail {
        using namespace curve25519;

        // Group element types
        struct ge {
            fe X;
            fe Y;
            fe Z;
            fe T;
        };
        struct ge_cached {
            fe Yp;
            fe Ym;
            fe Z;
            fe T2;
        };
        struct ge_precomp {
            fe Yp;
            fe Ym;
            fe T2;
        };

        inline void ge_zero(ge *p) {
            fe_0(p->X);
            fe_1(p->Y);
            fe_1(p->Z);
            fe_0(p->T);
        }

        inline void ge_tobytes(u8 s[32], const ge *h) {
            fe recip, x, y;
            fe_invert(recip, h->Z);
            fe_mul(x, h->X, recip);
            fe_mul(y, h->Y, recip);
            fe_tobytes(s, y);
            s[31] ^= fe_isodd(x) << 7;
            CURVE25519_WIPE_BUFFER(recip);
            CURVE25519_WIPE_BUFFER(x);
            CURVE25519_WIPE_BUFFER(y);
        }

        inline int ge_frombytes_neg_vartime(ge *h, const u8 s[32]) {
            fe d_copy;
            CURVE25519_COPY(d_copy, d_data, 10);

            fe_frombytes(h->Y, s);
            fe_1(h->Z);
            fe_sq(h->T, h->Y);
            fe_mul(h->X, h->T, d_copy);
            fe_sub(h->T, h->T, h->Z);
            fe_add(h->X, h->X, h->Z);
            fe_mul(h->X, h->T, h->X);
            int is_square = invsqrt(h->X, h->X);
            if (!is_square) {
                return -1;
            }
            fe_mul(h->X, h->T, h->X);
            if (fe_isodd(h->X) == (s[31] >> 7)) {
                fe_neg(h->X, h->X);
            }
            fe_mul(h->T, h->X, h->Y);
            return 0;
        }

        inline void ge_cache(ge_cached *c, const ge *p) {
            fe D2_copy;
            CURVE25519_COPY(D2_copy, D2_data, 10);

            fe_add(c->Yp, p->Y, p->X);
            fe_sub(c->Ym, p->Y, p->X);
            fe_copy(c->Z, p->Z);
            fe_mul(c->T2, p->T, D2_copy);
        }

        inline void ge_add(ge *s, const ge *p, const ge_cached *q) {
            fe a, b;
            fe_add(a, p->Y, p->X);
            fe_sub(b, p->Y, p->X);
            fe_mul(a, a, q->Yp);
            fe_mul(b, b, q->Ym);
            fe_add(s->Y, a, b);
            fe_sub(s->X, a, b);

            fe_add(s->Z, p->Z, p->Z);
            fe_mul(s->Z, s->Z, q->Z);
            fe_mul(s->T, p->T, q->T2);
            fe_add(a, s->Z, s->T);
            fe_sub(b, s->Z, s->T);

            fe_mul(s->T, s->X, s->Y);
            fe_mul(s->X, s->X, b);
            fe_mul(s->Y, s->Y, a);
            fe_mul(s->Z, a, b);
        }

        inline void ge_sub(ge *s, const ge *p, const ge_cached *q) {
            ge_cached neg;
            fe_copy(neg.Ym, q->Yp);
            fe_copy(neg.Yp, q->Ym);
            fe_copy(neg.Z, q->Z);
            fe_neg(neg.T2, q->T2);
            ge_add(s, p, &neg);
        }

        inline void ge_madd(ge *s, const ge *p, const ge_precomp *q, fe a, fe b) {
            fe_add(a, p->Y, p->X);
            fe_sub(b, p->Y, p->X);
            fe_mul(a, a, q->Yp);
            fe_mul(b, b, q->Ym);
            fe_add(s->Y, a, b);
            fe_sub(s->X, a, b);

            fe_add(s->Z, p->Z, p->Z);
            fe_mul(s->T, p->T, q->T2);
            fe_add(a, s->Z, s->T);
            fe_sub(b, s->Z, s->T);

            fe_mul(s->T, s->X, s->Y);
            fe_mul(s->X, s->X, b);
            fe_mul(s->Y, s->Y, a);
            fe_mul(s->Z, a, b);
        }

        inline void ge_double(ge *s, const ge *p, ge *q) {
            fe_sq(q->X, p->X);
            fe_sq(q->Y, p->Y);
            fe_sq(q->Z, p->Z);
            fe_mul_small(q->Z, q->Z, 2);
            fe_add(q->T, p->X, p->Y);
            fe_sq(s->T, q->T);
            fe_add(q->T, q->Y, q->X);
            fe_sub(q->Y, q->Y, q->X);
            fe_sub(q->X, s->T, q->T);
            fe_sub(q->Z, q->Z, q->Y);

            fe_mul(s->X, q->X, q->Z);
            fe_mul(s->Y, q->T, q->Y);
            fe_mul(s->Z, q->Y, q->Z);
            fe_mul(s->T, q->X, q->T);
        }

        // Base point precomputed table (5-bit signed window)
        inline const ge_precomp b_window[8] = {
            {
                {25967493, -14356035, 29566456, 3660896, -12694345, 4014787, 27544626, -11754271, -6079156, 2047605},
                {-12545711, 934262, -2722910, 3049990, -727428, 9406986, 12720692, 5043384, 19500929, -15469378},
                {-8738181, 4489570, 9688441, -14785194, 10184609, -12363380, 29287919, 11864899, -24514362, -4438546},
            },
            {
                {15636291, -9688557, 24204773, -7912398, 616977, -16685262, 27787600, -14772189, 28944400, -1550024},
                {16568933, 4717097, -11556148, -1102322, 15682896, -11807043, 16354577, -11775962, 7689662, 11199574},
                {30464156, -5976125, -11779434, -15670865, 23220365, 15915852, 7512774, 10017326, -17749093, -9920357},
            },
            {
                {10861363, 11473154, 27284546, 1981175, -30064349, 12577861, 32867885, 14515107, -15438304, 10819380},
                {4708026, 6336745, 20377586, 9066809, -11272109, 6594696, -25653668, 12483688, -12668491, 5581306},
                {19563160, 16186464, -29386857, 4097519, 10237984, -4348115, 28542350, 13850243, -23678021, -15815942},
            },
            {
                {5153746, 9909285, 1723747, -2777874, 30523605, 5516873, 19480852, 5230134, -23952439, -15175766},
                {-30269007, -3463509, 7665486, 10083793, 28475525, 1649722, 20654025, 16520125, 30598449, 7715701},
                {28881845, 14381568, 9657904, 3680757, -20181635, 7843316, -31400660, 1370708, 29794553, -1409300},
            },
            {
                {-22518993, -6692182, 14201702, -8745502, -23510406, 8844726, 18474211, -1361450, -13062696, 13821877},
                {-6455177, -7839871, 3374702, -4740862, -27098617, -10571707, 31655028, -7212327, 18853322, -14220951},
                {4566830, -12963868, -28974889, -12240689, -7602672, -2830569, -8514358, -10431137, 2207753, -3209784},
            },
            {
                {-25154831, -4185821, 29681144, 7868801, -6854661, -9423865, -12437364, -663000, -31111463, -16132436},
                {25576264, -2703214, 7349804, -11814844, 16472782, 9300885, 3844789, 15725684, 171356, 6466918},
                {23103977, 13316479, 9739013, -16149481, 817875, -15038942, 8965339, -14088058, -30714912, 16193877},
            },
            {
                {-33521811, 3180713, -2394130, 14003687, -16903474, -16270840, 17238398, 4729455, -18074513, 9256800},
                {-25182317, -4174131, 32336398, 5036987, -21236817, 11360617, 22616405, 9761698, -19827198, 630305},
                {-13720693, 2639453, -24237460, -7406481, 9494427, -5774029, -6554551, -15960994, -2449256, -14291300},
            },
            {
                {-3151181, -5046075, 9282714, 6866145, -31907062, -863023, -18940575, 15033784, 25105118, -7894876},
                {-24326370, 15950226, -31801215, -14592823, -11662737, -5090925, 1573892, -2625887, 2198790, -15804619},
                {-3099351, 10324967, -2241613, 7453183, -5446979, -2735503, -13812022, -16236442, -32461234, -12290683},
            },
        };

        // Precomputed comb tables for efficient scalar multiplication
        inline const ge_precomp b_comb_low[8] = {
            {
                {-6816601, -2324159, -22559413, 124364, 18015490, 8373481, 19993724, 1979872, -18549925, 9085059},
                {10306321, 403248, 14839893, 9633706, 8463310, -8354981, -14305673, 14668847, 26301366, 2818560},
                {-22701500, -3210264, -13831292, -2927732, -16326337, -14016360, 12940910, 177905, 12165515, -2397893},
            },
            {
                {-12282262, -7022066, 9920413, -3064358, -32147467, 2927790, 22392436, -14852487, 2719975, 16402117},
                {-7236961, -4729776, 2685954, -6525055, -24242706, -15940211, -6238521, 14082855, 10047669, 12228189},
                {-30495588, -12893761, -11161261, 3539405, -11502464, 16491580, -27286798, -15030530, -7272871,
                 -15934455},
            },
            {
                {17650926, 582297, -860412, -187745, -12072900, -10683391, -20352381, 15557840, -31072141, -5019061},
                {-6283632, -2259834, -4674247, -4598977, -4089240, 12435688, -31278303, 1060251, 6256175, 10480726},
                {-13871026, 2026300, -21928428, -2741605, -2406664, -8034988, 7355518, 15733500, -23379862, 7489131},
            },
            {
                {6883359, 695140, 23196907, 9644202, -33430614, 11354760, -20134606, 6388313, -8263585, -8491918},
                {-7716174, -13605463, -13646110, 14757414, -19430591, -14967316, 10359532, -11059670, -21935259,
                 12082603},
                {-11253345, -15943946, 10046784, 5414629, 24840771, 8086951, -6694742, 9868723, 15842692, -16224787},
            },
            {
                {9639399, 11810955, -24007778, -9320054, 3912937, -9856959, 996125, -8727907, -8919186, -14097242},
                {7248867, 14468564, 25228636, -8795035, 14346339, 8224790, 6388427, -7181107, 6468218, -8720783},
                {15513115, 15439095, 7342322, -10157390, 18005294, -7265713, 2186239, 4884640, 10826567, 7135781},
            },
            {
                {-14204238, 5297536, -5862318, -6004934, 28095835, 4236101, -14203318, 1958636, -16816875, 3837147},
                {-5511166, -13176782, -29588215, 12339465, 15325758, -15945770, -8813185, 11075932, -19608050,
                 -3776283},
                {11728032, 9603156, -4637821, -5304487, -7827751, 2724948, 31236191, -16760175, -7268616, 14799772},
            },
            {
                {-28842672, 4840636, -12047946, -9101456, -1445464, 381905, -30977094, -16523389, 1290540, 12798615},
                {27246947, -10320914, 14792098, -14518944, 5302070, -8746152, -3403974, -4149637, -27061213, 10749585},
                {25572375, -6270368, -15353037, 16037944, 1146292, 32198, 23487090, 9585613, 24714571, -1418265},
            },
            {
                {19844825, 282124, -17583147, 11004019, -32004269, -2716035, 6105106, -1711007, -21010044, 14338445},
                {8027505, 8191102, -18504907, -12335737, 25173494, -5923905, 15446145, 7483684, -30440441, 10009108},
                {-14134701, -4174411, 10246585, -14677495, 33553567, -14012935, 23366126, 15080531, -7969992, 7663473},
            },
        };

        inline const ge_precomp b_comb_high[8] = {
            {
                {33055887, -4431773, -521787, 6654165, 951411, -6266464, -5158124, 6995613, -5397442, -6985227},
                {4014062, 6967095, -11977872, 3960002, 8001989, 5130302, -2154812, -1899602, -31954493, -16173976},
                {16271757, -9212948, 23792794, 731486, -25808309, -3546396, 6964344, -4767590, 10976593, 10050757},
            },
            {
                {2533007, -4288439, -24467768, -12387405, -13450051, 14542280, 12876301, 13893535, 15067764, 8594792},
                {20073501, -11623621, 3165391, -13119866, 13188608, -11540496, -10751437, -13482671, 29588810, 2197295},
                {-1084082, 11831693, 6031797, 14062724, 14748428, -8159962, -20721760, 11742548, 31368706, 13161200},
            },
            {
                {2050412, -6457589, 15321215, 5273360, 25484180, 124590, -18187548, -7097255, -6691621, -14604792},
                {9938196, 2162889, -6158074, -1711248, 4278932, -2598531, -22865792, -7168500, -24323168, 11746309},
                {-22691768, -14268164, 5965485, 9383325, 20443693, 5854192, 28250679, -1381811, -10837134, 13717818},
            },
            {
                {-8495530, 16382250, 9548884, -4971523, -4491811, -3902147, 6182256, -12832479, 26628081, 10395408},
                {27329048, -15853735, 7715764, 8717446, -9215518, -14633480, 28982250, -5668414, 4227628, 242148},
                {-13279943, -7986904, -7100016, 8764468, -27276630, 3096719, 29678419, -9141299, 3906709, 11265498},
            },
            {
                {11918285, 15686328, -17757323, -11217300, -27548967, 4853165, -27168827, 6807359, 6871949, -1075745},
                {-29002610, 13984323, -27111812, -2713442, 28107359, -13266203, 6155126, 15104658, 3538727, -7513788},
                {14103158, 11233913, -33165269, 9279850, 31014152, 4335090, -1827936, 4590951, 13960841, 12787712},
            },
            {
                {1469134, -16738009, 33411928, 13942824, 8092558, -8778224, -11165065, 1437842, 22521552, -2792954},
                {31352705, -4807352, -25327300, 3962447, 12541566, -9399651, -27425693, 7964818, -23829869, 5541287},
                {-25732021, -6864887, 23848984, 3039395, -9147354, 6022816, -27421653, 10590137, 25309915, -1584678},
            },
            {
                {-22951376, 5048948, 31139401, -190316, -19542447, -626310, -17486305, -16511925, -18851313, -12985140},
                {-9684890, 14681754, 30487568, 7717771, -10829709, 9630497, 30290549, -10531496, -27798994, -13812825},
                {5827835, 16097107, -24501327, 12094619, 7413972, 11447087, 28057551, -1793987, -14056981, 4359312},
            },
            {
                {26323183, 2342588, -21887793, -1623758, -6062284, 2107090, -28724907, 9036464, -19618351, -13055189},
                {-29697200, 14829398, -4596333, 14220089, -30022969, 2955645, 12094100, -13693652, -5941445, 7047569},
                {-3201977, 14413268, -12058324, -16417589, -9035655, -7224648, 9258160, 1399236, 30397584, -5684634},
            },
        };

        inline void ge_msub(ge *s, const ge *p, const ge_precomp *q, fe a, fe b) {
            ge_precomp neg;
            fe_copy(neg.Ym, q->Yp);
            fe_copy(neg.Yp, q->Ym);
            fe_neg(neg.T2, q->T2);
            ge_madd(s, p, &neg, a, b);
        }

        inline void lookup_add(ge *p, ge_precomp *tmp_c, fe tmp_a, fe tmp_b, const ge_precomp comb[8],
                               const u8 scalar[32], int i) {
            u8 teeth = (u8)((scalar_bit(scalar, i)) + (scalar_bit(scalar, i + 32) << 1) +
                            (scalar_bit(scalar, i + 64) << 2) + (scalar_bit(scalar, i + 96) << 3));
            u8 high = teeth >> 3;
            u8 index = (teeth ^ (high - 1)) & 7;
            CURVE25519_FOR(j, 0, 8) {
                i32 select = 1 & (((j ^ index) - 1) >> 8);
                fe_ccopy(tmp_c->Yp, comb[j].Yp, select);
                fe_ccopy(tmp_c->Ym, comb[j].Ym, select);
                fe_ccopy(tmp_c->T2, comb[j].T2, select);
            }
            fe_neg(tmp_a, tmp_c->T2);
            fe_cswap(tmp_c->T2, tmp_a, high ^ 1);
            fe_cswap(tmp_c->Yp, tmp_c->Ym, high ^ 1);
            ge_madd(p, p, tmp_c, tmp_a, tmp_b);
        }

        inline void ge_scalarmult_base(ge *p, const u8 scalar[32]) {
            // 1 / 2 modulo L
            static const u8 half_mod_L[32] = {
                247, 233, 122, 46, 141, 49, 9, 44, 107, 206, 123, 81, 239, 124, 111, 10,
                0,   0,   0,   0,  0,   0,  0, 0,  0,   0,   0,   0,  0,   0,   0,   8,
            };
            // (2^256 - 1) / 2 modulo L
            static const u8 half_ones[32] = {
                142, 74,  204, 70,  186, 24,  118, 107, 184, 231, 190, 57,  250, 173, 119, 99,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 7,
            };

            u8 s_scalar[32];
            mul_add(s_scalar, scalar, half_mod_L, half_ones);

            fe tmp_a, tmp_b;
            ge_precomp tmp_c;
            ge tmp_d;
            fe_1(tmp_c.Yp);
            fe_1(tmp_c.Ym);
            fe_0(tmp_c.T2);

            ge_zero(p);
            lookup_add(p, &tmp_c, tmp_a, tmp_b, b_comb_low, s_scalar, 31);
            lookup_add(p, &tmp_c, tmp_a, tmp_b, b_comb_high, s_scalar, 31 + 128);
            for (int i = 30; i >= 0; i--) {
                ge_double(p, p, &tmp_d);
                lookup_add(p, &tmp_c, tmp_a, tmp_b, b_comb_low, s_scalar, i);
                lookup_add(p, &tmp_c, tmp_a, tmp_b, b_comb_high, s_scalar, i + 128);
            }

            CURVE25519_WIPE_BUFFER(tmp_a);
            CURVE25519_WIPE_BUFFER(tmp_b);
            CURVE25519_WIPE_BUFFER(s_scalar);
        }

        inline void scalarbase(u8 point[32], const u8 scalar[32]) {
            ge P;
            ge_scalarmult_base(&P, scalar);
            ge_tobytes(point, &P);
        }

        // Sliding window context for verification
        struct slide_ctx {
            i16 next_index;
            i8 next_digit;
            u8 next_check;
        };

        inline void slide_init(slide_ctx *ctx, const u8 scalar[32]) {
            int i = 252;
            while (i > 0 && scalar_bit(scalar, i) == 0) {
                i--;
            }
            ctx->next_check = (u8)(i + 1);
            ctx->next_index = -1;
            ctx->next_digit = -1;
        }

        inline int slide_step(slide_ctx *ctx, int width, int i, const u8 scalar[32]) {
            if (i == ctx->next_check) {
                if (scalar_bit(scalar, i) == scalar_bit(scalar, i - 1)) {
                    ctx->next_check--;
                } else {
                    int w = CURVE25519_MIN(width, i + 1);
                    int v = -(scalar_bit(scalar, i) << (w - 1));
                    for (int j = 0; j < w - 1; j++) {
                        v += scalar_bit(scalar, i - (w - 1) + j) << j;
                    }
                    v += scalar_bit(scalar, i - w);
                    int lsb = v & (~v + 1);
                    int s = (((lsb & 0xAA) != 0) << 0) | (((lsb & 0xCC) != 0) << 1) | (((lsb & 0xF0) != 0) << 2);
                    ctx->next_index = (i16)(i - (w - 1) + s);
                    ctx->next_digit = (i8)(v >> s);
                    ctx->next_check -= (u8)w;
                }
            }
            return i == ctx->next_index ? ctx->next_digit : 0;
        }

#define P_W_WIDTH 3
#define B_W_WIDTH 5
#define P_W_SIZE (1 << (P_W_WIDTH - 2))

        // Check Ed25519 signature equation: [s]B = R + [h]A
        inline int check_equation(const u8 signature[64], const u8 public_key[32], const u8 h[32]) {
            ge minus_A;
            ge minus_R;
            const u8 *s = signature + 32;

            // Check that A and R are on the curve
            // Check that 0 <= S < L
            {
                u32 s32[8];
                load32_le_buf(s32, s, 8);
                if (ge_frombytes_neg_vartime(&minus_A, public_key) || ge_frombytes_neg_vartime(&minus_R, signature) ||
                    is_above_l(s32)) {
                    return -1;
                }
            }

            // Build lookup table for minus_A
            ge_cached lutA[P_W_SIZE];
            {
                ge minus_A2, tmp;
                ge_double(&minus_A2, &minus_A, &tmp);
                ge_cache(&lutA[0], &minus_A);
                CURVE25519_FOR(i, 1, P_W_SIZE) {
                    ge_add(&tmp, &minus_A2, &lutA[i - 1]);
                    ge_cache(&lutA[i], &tmp);
                }
            }

            // Compute sum = [s]B - [h]A using double-and-add with sliding windows
            slide_ctx h_slide;
            slide_init(&h_slide, h);
            slide_ctx s_slide;
            slide_init(&s_slide, s);
            int i = CURVE25519_MAX(h_slide.next_check, s_slide.next_check);
            ge *sum = &minus_A;
            ge_zero(sum);
            while (i >= 0) {
                ge tmp;
                ge_double(sum, sum, &tmp);
                int h_digit = slide_step(&h_slide, P_W_WIDTH, i, h);
                int s_digit = slide_step(&s_slide, B_W_WIDTH, i, s);
                if (h_digit > 0) {
                    ge_add(sum, sum, &lutA[h_digit / 2]);
                }
                if (h_digit < 0) {
                    ge_sub(sum, sum, &lutA[-h_digit / 2]);
                }
                fe t1, t2;
                if (s_digit > 0) {
                    ge_madd(sum, sum, b_window + s_digit / 2, t1, t2);
                }
                if (s_digit < 0) {
                    ge_msub(sum, sum, b_window + -s_digit / 2, t1, t2);
                }
                i--;
            }

            // Compare [8](sum-R) and the zero point
            ge_cached cached;
            u8 check[32];
            static const u8 zero_point[32] = {1};
            ge_cache(&cached, &minus_R);
            ge_add(sum, sum, &cached);
            ge_double(sum, sum, &minus_R);
            ge_double(sum, sum, &minus_R);
            ge_double(sum, sum, &minus_R);
            ge_tobytes(check, sum);
            return crypto_verify32(check, zero_point);
        }

#undef P_W_WIDTH
#undef B_W_WIDTH
#undef P_W_SIZE

        // Hash and reduce modulo L for Ed25519
        inline void hash_reduce(uint8_t h[32], const uint8_t *a, size_t a_size, const uint8_t *b, size_t b_size,
                                const uint8_t *c, size_t c_size, const uint8_t *d, size_t d_size) {
            uint8_t hash[64];
            keylock::hash::sha512::Context ctx;
            keylock::hash::sha512::init(&ctx);
            if (a && a_size > 0)
                keylock::hash::sha512::update(&ctx, a, a_size);
            if (b && b_size > 0)
                keylock::hash::sha512::update(&ctx, b, b_size);
            if (c && c_size > 0)
                keylock::hash::sha512::update(&ctx, c, c_size);
            if (d && d_size > 0)
                keylock::hash::sha512::update(&ctx, d, d_size);
            keylock::hash::sha512::final(&ctx, hash);
            reduce(h, hash);
            constant_time::wipe(hash, sizeof(hash));
        }

    } // namespace detail

    // Generate Ed25519 keypair from seed
    // secret_key is 64 bytes: first 32 are the seed, last 32 are the public key
    inline void seed_keypair(uint8_t public_key[32], uint8_t secret_key[64], const uint8_t seed[32]) {
        using namespace curve25519;

        uint8_t a[64];
        // Copy seed to secret key first half
        for (int i = 0; i < 32; i++) {
            secret_key[i] = seed[i];
        }

        // Hash seed with SHA-512 to get scalar (first 32 bytes) and prefix (last 32 bytes)
        keylock::hash::sha512::hash(a, seed, 32);

        // Clamp the scalar (first 32 bytes)
        trim_scalar(a, a);

        // Compute public key = [scalar]B
        detail::scalarbase(public_key, a);

        // Store public key in secret_key (second half)
        for (int i = 0; i < 32; i++) {
            secret_key[32 + i] = public_key[i];
        }

        constant_time::wipe(a, sizeof(a));
    }

    // Generate Ed25519 keypair with random seed
    inline void keypair(uint8_t public_key[32], uint8_t secret_key[64]) {
        uint8_t seed[32];
        rng::randombytes_buf(seed, sizeof(seed));
        seed_keypair(public_key, secret_key, seed);
        constant_time::wipe(seed, sizeof(seed));
    }

    // Sign message with Ed25519 (detached signature)
    // Returns 0 on success
    inline int sign_detached(uint8_t signature[64], unsigned long long *siglen, const uint8_t *message,
                             unsigned long long message_size, const uint8_t secret_key[64]) {
        using namespace curve25519;

        uint8_t a[64]; // secret scalar (clamped) and prefix
        uint8_t r[32]; // secret deterministic nonce
        uint8_t h[32]; // hash for verification
        uint8_t R[32]; // first half of signature
        const uint8_t *pk = secret_key + 32;

        // Hash the secret key seed to get scalar and prefix
        keylock::hash::sha512::hash(a, secret_key, 32);
        trim_scalar(a, a);

        // r = H(prefix || message) mod L
        detail::hash_reduce(r, a + 32, 32, message, message_size, nullptr, 0, nullptr, 0);

        // R = [r]B
        detail::scalarbase(R, r);

        // h = H(R || pk || message) mod L
        detail::hash_reduce(h, R, 32, pk, 32, message, message_size, nullptr, 0);

        // Copy R to first half of signature
        for (int i = 0; i < 32; i++) {
            signature[i] = R[i];
        }

        // s = (r + h * a) mod L
        mul_add(signature + 32, h, a, r);

        constant_time::wipe(a, sizeof(a));
        constant_time::wipe(r, sizeof(r));

        if (siglen) {
            *siglen = 64;
        }
        return 0;
    }

    // Verify Ed25519 signature (detached)
    // Returns 0 if valid, -1 if invalid
    inline int verify_detached(const uint8_t signature[64], const uint8_t *message, unsigned long long message_size,
                               const uint8_t public_key[32]) {
        // Compute h = H(R || pk || message) mod L
        uint8_t h_ram[32];
        detail::hash_reduce(h_ram, signature, 32, public_key, 32, message, message_size, nullptr, 0);

        // Verify the signature equation: [s]B = R + [h]A
        return detail::check_equation(signature, public_key, h_ram);
    }

} // namespace keylock::crypto::ed25519
