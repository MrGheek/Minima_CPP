/**
 * test_serialization.cpp - Serialization parity test for base primitives
 *
 * Tests round-trip writeDataStream/readDataStream for:
 *   MiniNumber, MiniData, MiniByte, MiniString
 *
 * Build: cmake --build <build-dir> --target test_serialization
 * Run:   ./build/test_serialization
 */

#include <cstdio>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>

#include "org/minima/objects/base/mini_data.hpp"
#include "org/minima/objects/base/mini_number.hpp"
#include "org/minima/objects/base/mini_byte.hpp"
#include "org/minima/objects/base/mini_string.hpp"

using org::minima::objects::base::MiniData;
using org::minima::objects::base::MiniNumber;
using org::minima::objects::base::MiniByte;
using org::minima::objects::base::MiniString;

static int pass = 0;
static int fail = 0;

static void check(bool condition, const char* description) {
    if (condition) {
        printf("[PASS] %s\n", description);
        ++pass;
    } else {
        printf("[FAIL] %s\n", description);
        ++fail;
    }
}

// ---------------------------------------------------------------------------
// MiniNumber
// ---------------------------------------------------------------------------

static void test_mini_number() {
    // Round-trip: integer zero
    {
        MiniNumber orig(0);
        std::ostringstream out;
        orig.writeDataStream(out);
        std::istringstream in(out.str());
        MiniNumber restored;
        restored.readDataStream(in);
        check(restored.isEqual(orig), "MiniNumber round-trip: 0");
    }

    // Round-trip: positive integer
    {
        MiniNumber orig(42);
        std::ostringstream out;
        orig.writeDataStream(out);
        std::istringstream in(out.str());
        MiniNumber restored;
        restored.readDataStream(in);
        check(restored.isEqual(orig), "MiniNumber round-trip: 42");
    }

    // Round-trip: large integer
    {
        MiniNumber orig(1000000);
        std::ostringstream out;
        orig.writeDataStream(out);
        std::istringstream in(out.str());
        MiniNumber restored;
        restored.readDataStream(in);
        check(restored.isEqual(orig), "MiniNumber round-trip: 1000000");
    }

    // Round-trip: decimal string
    {
        MiniNumber orig("123.456");
        std::ostringstream out;
        orig.writeDataStream(out);
        std::istringstream in(out.str());
        MiniNumber restored;
        restored.readDataStream(in);
        check(restored.isEqual(orig), "MiniNumber round-trip: 123.456");
    }

    // Arithmetic sanity
    {
        MiniNumber a(10);
        MiniNumber b(5);
        MiniNumber sum = a.add(b);
        check(sum.isEqual(MiniNumber(15)), "MiniNumber: 10 + 5 = 15");
        MiniNumber diff = a.sub(b);
        check(diff.isEqual(MiniNumber(5)), "MiniNumber: 10 - 5 = 5");
        MiniNumber prod = a.mult(b);
        check(prod.isEqual(MiniNumber(50)), "MiniNumber: 10 * 5 = 50");
    }

    // Comparisons
    {
        MiniNumber a(3);
        MiniNumber b(7);
        check(a.isLess(b),       "MiniNumber: 3 < 7");
        check(b.isMore(a),       "MiniNumber: 7 > 3");
        check(!a.isEqual(b),     "MiniNumber: 3 != 7");
        check(a.isEqual(a),      "MiniNumber: 3 == 3");
    }
}

// ---------------------------------------------------------------------------
// MiniData
// ---------------------------------------------------------------------------

static void test_mini_data() {
    // Round-trip: empty
    {
        MiniData orig;
        std::ostringstream out;
        orig.writeDataStream(out);
        std::istringstream in(out.str());
        MiniData restored;
        restored.readDataStream(in);
        check(restored.isEqual(orig), "MiniData round-trip: empty");
    }

    // Round-trip: from hex string
    {
        MiniData orig("0xdeadbeef");
        std::ostringstream out;
        orig.writeDataStream(out);
        std::istringstream in(out.str());
        MiniData restored;
        restored.readDataStream(in);
        check(restored.isEqual(orig), "MiniData round-trip: 0xdeadbeef");
    }

    // Round-trip: from byte vector
    {
        std::vector<uint8_t> bytes = {0x01, 0x02, 0x03, 0xff, 0x00};
        MiniData orig(bytes);
        std::ostringstream out;
        orig.writeDataStream(out);
        std::istringstream in(out.str());
        MiniData restored;
        restored.readDataStream(in);
        check(restored.isEqual(orig), "MiniData round-trip: byte vector");
    }

    // Length accessor
    {
        std::vector<uint8_t> bytes = {0x01, 0x02, 0x03};
        MiniData d(bytes);
        check(d.getLength() == 3, "MiniData: getLength() == 3");
    }

    // Equality
    {
        MiniData a("0x1234");
        MiniData b("0x1234");
        MiniData c("0x5678");
        check(a.isEqual(b),  "MiniData: equal");
        check(!a.isEqual(c), "MiniData: not equal");
    }
}

// ---------------------------------------------------------------------------
// MiniByte
// ---------------------------------------------------------------------------

static void test_mini_byte() {
    // Round-trip: 0
    {
        MiniByte orig(0);
        std::ostringstream out;
        orig.writeDataStream(out);
        std::istringstream in(out.str());
        MiniByte restored;
        restored.readDataStream(in);
        check(restored.isEqual(orig), "MiniByte round-trip: 0");
    }

    // Round-trip: 255
    {
        MiniByte orig(255);
        std::ostringstream out;
        orig.writeDataStream(out);
        std::istringstream in(out.str());
        MiniByte restored;
        restored.readDataStream(in);
        check(restored.isEqual(orig), "MiniByte round-trip: 255");
    }

    // Round-trip: true
    {
        MiniByte orig(true);
        std::ostringstream out;
        orig.writeDataStream(out);
        std::istringstream in(out.str());
        MiniByte restored;
        restored.readDataStream(in);
        check(restored.isTrue(),  "MiniByte round-trip: true");
    }

    // Round-trip: false
    {
        MiniByte orig(false);
        std::ostringstream out;
        orig.writeDataStream(out);
        std::istringstream in(out.str());
        MiniByte restored;
        restored.readDataStream(in);
        check(restored.isFalse(), "MiniByte round-trip: false");
    }

    // Equality
    {
        MiniByte a(42), b(42), c(7);
        check(a.isEqual(b),  "MiniByte: equal");
        check(!a.isEqual(c), "MiniByte: not equal");
    }
}

// ---------------------------------------------------------------------------
// MiniString
// ---------------------------------------------------------------------------

static void test_mini_string() {
    // Round-trip: empty
    {
        MiniString orig;
        std::ostringstream out;
        orig.writeDataStream(out);
        std::istringstream in(out.str());
        MiniString restored;
        restored.readDataStream(in);
        check(restored.isEqual(""), "MiniString round-trip: empty");
    }

    // Round-trip: simple ASCII
    {
        MiniString orig("hello");
        std::ostringstream out;
        orig.writeDataStream(out);
        std::istringstream in(out.str());
        MiniString restored;
        restored.readDataStream(in);
        check(restored.isEqual("hello"), "MiniString round-trip: hello");
    }

    // Round-trip: longer string
    {
        std::string s(100, 'x');
        MiniString orig(s);
        std::ostringstream out;
        orig.writeDataStream(out);
        std::istringstream in(out.str());
        MiniString restored;
        restored.readDataStream(in);
        check(restored.isEqual(s), "MiniString round-trip: 100 chars");
    }

    // Equality
    {
        MiniString a("foo"), b("foo"), c("bar");
        check(a.isEqual("foo"),    "MiniString: equal");
        check(!a.isEqual("bar"),   "MiniString: not equal");
        (void)b; (void)c;
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    printf("=== MiniNumber ===\n");
    test_mini_number();
    printf("\n=== MiniData ===\n");
    test_mini_data();
    printf("\n=== MiniByte ===\n");
    test_mini_byte();
    printf("\n=== MiniString ===\n");
    test_mini_string();

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
