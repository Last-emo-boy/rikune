#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#define RETAIN __attribute__((used))
#else
#define NOINLINE
#define RETAIN
#endif

enum { TOKEN_LENGTH = 24 };

static const uint8_t byte_mask[] = {0x91, 0x27, 0x6d, 0xc3, 0x4a, 0xfe, 0x18, 0xb5};
static const uint8_t byte_salt[] = {0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac};
static const uint8_t expected_bytes[TOKEN_LENGTH] = {
    0x59, 0x95, 0xb2, 0x1a, 0x24, 0xde, 0x74, 0x2a,
    0x5f, 0xeb, 0x4e, 0xc6, 0xd5, 0x73, 0x49, 0x53,
    0x7f, 0xca, 0x94, 0x12, 0x07, 0x32, 0x75, 0x9f,
};
static const uint8_t verification_order[TOKEN_LENGTH] = {
    17, 3, 22, 8, 14, 0, 19, 6, 11, 23, 2, 15,
    9, 20, 5, 12, 1, 18, 7, 21, 4, 16, 10, 13,
};

static const uint8_t accepted_message[] = {
    0x1c, 0x09, 0x14, 0xe1, 0xe2, 0xed, 0x8b, 0xd9, 0xa6, 0xb1,
    0xba, 0x9c, 0x8d, 0x63, 0x77, 0x0e, 0x0d, 0x79, 0x26, 0x27,
    0x04, 0x4e, 0x0f, 0xe7, 0xfe, 0xc7, 0xc1, 0x9c, 0xbc, 0xb8,
    0x8f, 0x9f, 0x9e, 0x61, 0x72, 0x40, 0x1f,
};
static const uint8_t denied_message[] = {
    0xe6, 0xd7, 0xa2, 0xab, 0xa8, 0x9b, 0xd5, 0x66, 0x6a, 0x72,
    0x40, 0x53, 0x27, 0x7e, 0x7d, 0x2f, 0x01, 0xed, 0xf5, 0xfb,
    0xc5, 0xdb, 0xa0, 0xf2, 0xb2, 0x85, 0x8a, 0x6b, 0x72, 0x54,
    0x4e, 0x52, 0x69,
};
static const uint8_t usage_message[] = {
    0x49, 0x3a, 0x37, 0x04, 0x15, 0x47, 0xaa, 0xf4, 0xcb, 0xdc,
    0xce, 0xa7, 0xbd, 0x9d, 0xad, 0x9c, 0x7e, 0x78, 0x45, 0x58,
    0x2d, 0x28, 0x7a, 0x5b, 0x46, 0xb5, 0xa3, 0xf9, 0xd1, 0xc1,
    0xa7, 0xef, 0xa8, 0x86, 0x9d, 0x66, 0x7e, 0x23,
};

static uint8_t rotate_left_8(uint8_t value, unsigned int amount) {
    amount &= 7U;
    return (uint8_t)((value << amount) | (value >> ((8U - amount) & 7U)));
}

static uint32_t rotate_left_32(uint32_t value, unsigned int amount) {
    amount &= 31U;
    return (value << amount) | (value >> ((32U - amount) & 31U));
}

static NOINLINE void emit_encoded(const uint8_t *encoded, size_t length, uint8_t key) {
    uint8_t decoded[96];
    size_t i;

    if (length > sizeof(decoded)) {
        return;
    }
    for (i = 0; i < length; ++i) {
        decoded[i] = (uint8_t)(encoded[i] ^ (uint8_t)(key + (uint8_t)(i * 13U)));
    }
    (void)fwrite(decoded, 1, length, stdout);
    (void)fputc('\n', stdout);
    memset(decoded, 0, sizeof(decoded));
}

static NOINLINE int gate_shape(const uint8_t *candidate) {
    size_t i;
    uint32_t rejected = 0;

    if (strlen((const char *)candidate) != TOKEN_LENGTH) {
        return 0;
    }
    for (i = 0; i < TOKEN_LENGTH; ++i) {
        uint8_t value = candidate[i];
        uint32_t separator = (i == 4U || i == 9U || i == 14U || i == 19U);
        uint32_t allowed = ((value >= 'A' && value <= 'Z') ||
                            (value >= '0' && value <= '9') || value == '!');
        rejected |= separator ? (uint32_t)(value != '-') : (uint32_t)!allowed;
    }
    return rejected == 0;
}

static NOINLINE int gate_permuted_bytes(const uint8_t *candidate) {
    size_t step;
    uint32_t difference = 0;

    for (step = 0; step < TOKEN_LENGTH; ++step) {
        size_t i = verification_order[step];
        uint8_t mixed = (uint8_t)(candidate[i] ^ byte_mask[i % sizeof(byte_mask)] ^
                                  (uint8_t)(i * 29U + 0x37U));
        mixed = rotate_left_8(mixed, (unsigned int)(i % 5U) + 1U);
        mixed = (uint8_t)((uint8_t)(mixed + byte_salt[i % sizeof(byte_salt)]) ^
                          (uint8_t)(0xa5U - i * 3U));
        difference |= (uint32_t)(mixed ^ expected_bytes[i]);
    }
    return difference == 0;
}

static NOINLINE int gate_state_machine(const uint8_t *candidate) {
    uint32_t state = UINT32_C(0x6d2b79f5);
    uint32_t lane0 = UINT32_C(0x13579bdf);
    uint32_t lane1 = UINT32_C(0x2468ace0);
    size_t i;

    for (i = 0; i < TOKEN_LENGTH; ++i) {
        uint32_t value = candidate[i];
        state ^= value + UINT32_C(0x7f4a7c15) + (state << 6U) + (state >> 2U);
        state = rotate_left_32(state, (unsigned int)(i % 13U) + 3U);
        state = state * UINT32_C(0x045d9f3b) + UINT32_C(0x27100001) + (uint32_t)i;
        if ((i & 1U) == 0U) {
            lane0 = (lane0 ^ (uint8_t)(candidate[i] + i * 11U)) * UINT32_C(0x01000193);
        } else {
            lane1 = (lane1 + (uint8_t)(candidate[i] ^ (uint8_t)(i * 17U))) *
                    UINT32_C(0x9e3779b1);
        }
    }

    return state == UINT32_C(0xe2978040) &&
           (lane0 ^ rotate_left_32(lane1, 7U)) == UINT32_C(0xff348a54);
}

static NOINLINE RETAIN int decoy_checksum(const uint8_t *candidate) {
    uint32_t state = UINT32_C(0xdeadbeef);
    size_t i;

    for (i = 0; i < TOKEN_LENGTH; ++i) {
        state = rotate_left_32(state ^ candidate[i], 5U) + UINT32_C(0x13371337);
    }
    return state == UINT32_C(0x5a17c0de);
}

typedef int (*gate_function)(const uint8_t *candidate);

static NOINLINE int validate_candidate(const uint8_t *candidate) {
    static gate_function const gates[] = {
        gate_permuted_bytes,
        gate_shape,
        gate_state_machine,
    };
    static const uint8_t order[] = {1, 0, 2};
    uint32_t result = 1;
    size_t i;

    for (i = 0; i < sizeof(order); ++i) {
        result &= (uint32_t)gates[order[i]](candidate);
    }
    return result == 1U;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        emit_encoded(usage_message, sizeof(usage_message), 0x3c);
        return 2;
    }

    if (validate_candidate((const uint8_t *)argv[1])) {
        emit_encoded(accepted_message, sizeof(accepted_message), 0x5d);
        return 0;
    }

    emit_encoded(denied_message, sizeof(denied_message), 0xa7);
    return 1;
}
