const std = @import("std");
const totp = @import("totp");
const expect = @import("expect").expect;
const extras = @import("extras");
const from_hex = extras.from_hex;

test {
    try expect(&totp.hotp(6, &.{ 0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a })).toEqualString("872921");
}

const seed = "3132333435363738393031323334353637383930";
const Sha1 = std.crypto.hash.Sha1;
// zig fmt: off
test { try expect(&totp.totp(8, Sha1, 0, 30, &from_hex(seed), 59)).toEqualString("94287082"); }
test { try expect(&totp.totp(8, Sha1, 0, 30, &from_hex(seed), 1111111109)).toEqualString("07081804"); }
test { try expect(&totp.totp(8, Sha1, 0, 30, &from_hex(seed), 1111111111)).toEqualString("14050471"); }
test { try expect(&totp.totp(8, Sha1, 0, 30, &from_hex(seed), 1234567890)).toEqualString("89005924"); }
test { try expect(&totp.totp(8, Sha1, 0, 30, &from_hex(seed), 2000000000)).toEqualString("69279037"); }
test { try expect(&totp.totp(8, Sha1, 0, 30, &from_hex(seed), 20000000000)).toEqualString("65353130"); }
// zig fmt: on

const seed32 = "3132333435363738393031323334353637383930313233343536373839303132";
const Sha256 = std.crypto.hash.sha2.Sha256;
// zig fmt: off
test { try expect(&totp.totp(8, Sha256, 0, 30, &from_hex(seed32), 59)).toEqualString("46119246"); }
test { try expect(&totp.totp(8, Sha256, 0, 30, &from_hex(seed32), 1111111109)).toEqualString("68084774"); }
test { try expect(&totp.totp(8, Sha256, 0, 30, &from_hex(seed32), 1111111111)).toEqualString("67062674"); }
test { try expect(&totp.totp(8, Sha256, 0, 30, &from_hex(seed32), 1234567890)).toEqualString("91819424"); }
test { try expect(&totp.totp(8, Sha256, 0, 30, &from_hex(seed32), 2000000000)).toEqualString("90698825"); }
test { try expect(&totp.totp(8, Sha256, 0, 30, &from_hex(seed32), 20000000000)).toEqualString("77737706"); }
// zig fmt: on

const seed64 = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334";
const Sha512 = std.crypto.hash.sha2.Sha512;
// zig fmt: off
test { try expect(&totp.totp(8, Sha512, 0, 30, &from_hex(seed64), 59)).toEqualString("90693936"); }
test { try expect(&totp.totp(8, Sha512, 0, 30, &from_hex(seed64), 1111111109)).toEqualString("25091201"); }
test { try expect(&totp.totp(8, Sha512, 0, 30, &from_hex(seed64), 1111111111)).toEqualString("99943326"); }
test { try expect(&totp.totp(8, Sha512, 0, 30, &from_hex(seed64), 1234567890)).toEqualString("93441116"); }
test { try expect(&totp.totp(8, Sha512, 0, 30, &from_hex(seed64), 2000000000)).toEqualString("38618901"); }
test { try expect(&totp.totp(8, Sha512, 0, 30, &from_hex(seed64), 20000000000)).toEqualString("47863826"); }
// zig fmt: on

test {
    const allocator = std.testing.allocator;
    const url = try totp.generateUrl(allocator, "ACME Co", "john.doe@email.com", &from_hex("3dc6caa4824a6d288767b2331e20b43166cb85d9"), .SHA1, 6, 30);
    defer allocator.free(url);
    try expect(url).toEqualString("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm=SHA1&digits=6&period=30");
}
test {
    const allocator = std.testing.allocator;
    const url = try totp.generateUrl(allocator, "Example", "alice@google.com", &from_hex("48656c6c6f21deadbeef"), .SHA1, 6, 30);
    defer allocator.free(url);
    try expect(url).toEqualString("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30");
}
test {
    const allocator = std.testing.allocator;
    const url = try totp.generateUrl(allocator, "otpauth demo", "username@example.org", &from_hex("0000008421d6b5adef7bc6318ce739f7bdefffff"), .SHA1, 6, 30);
    defer allocator.free(url);
    try expect(url).toEqualString("otpauth://totp/otpauth%20demo:username@example.org?secret=AAAABBBB22223333YYYYZZZZ66667777&algorithm=SHA1&digits=6&period=30");
}
