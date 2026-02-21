const std = @import("std");
const extras = @import("extras");
const url = @import("url");

pub fn totp(digits: comptime_int, Hash: type, epoch: u64, X: u64, K: *const [Hash.digest_length]u8, time_now_s: u64) [digits]u8 {
    const T = (time_now_s - epoch) / X;
    var Thex: [16]u8 = undefined;
    _ = std.fmt.bufPrint(&Thex, "{X:0>16}", .{T}) catch unreachable;
    const Hmac = std.crypto.auth.hmac.Hmac(Hash);
    var HS: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&HS, &extras.from_hex(&Thex), K);
    return hotp(digits, &HS);
}

pub fn hotp(digits: comptime_int, hmac_sha: []const u8) [digits]u8 {
    const last = hmac_sha[hmac_sha.len - 1];
    const offset = last & 0xf;
    const value: u31 = @truncate(std.mem.readInt(u32, hmac_sha[offset..][0..4], .big));
    const dbc = value % powci(10, digits);

    var out: [digits]u8 = undefined;
    for (0..digits) |i| out[digits - 1 - i] = @intCast(dbc / (std.math.powi(u32, 10, @intCast(i)) catch unreachable) % 10);
    for (0..digits) |i| out[i] += '0';
    return out;
}

fn powci(x: comptime_int, y: comptime_int) comptime_int {
    if (y < 0) @compileError("use sqrt etc");
    if (y == 0) return 1;
    return x * powci(x, y - 1);
}

pub const Algorithm = enum {
    SHA1,
    SHA256,
    SHA512,

    pub fn ty(algo: Algorithm) type {
        return switch (algo) {
            .SHA1 => std.crypto.hash.Sha1,
            .SHA256 => std.crypto.hash.sha2.Sha256,
            .SHA512 => std.crypto.hash.sha2.Sha512,
        };
    }

    pub fn digest_length(algo: Algorithm) u8 {
        return switch (algo) {
            inline else => |tag| tag.ty().digest_length,
        };
    }
};

pub fn generateUrl(allocator: std.mem.Allocator, issuer: []const u8, account: []const u8, secret_raw: []const u8, algo: Algorithm, digits: u8, period: u8) ![]const u8 {
    std.debug.assert(issuer.len > 0);
    std.debug.assert(account.len > 0);
    std.debug.assert(secret_raw.len == algo.digest_length());
    std.debug.assert(digits == 6 or digits == 7 or digits == 8);
    std.debug.assert(period == 15 or period == 30 or period == 60);
    var list: std.ArrayList(u8) = .init(allocator);
    errdefer list.deinit();
    try list.appendSlice("otpauth://");
    try list.appendSlice("totp/");
    try url.percentEncodeAL(&list, issuer, url.is_path_percent_char);
    try list.append(':');
    try url.percentEncodeAL(&list, account, url.is_path_percent_char);
    try list.appendSlice("?secret=");
    try encodeBase32(&list, secret_raw);
    try list.appendSlice("&algorithm=");
    try list.appendSlice(@tagName(algo));
    try list.appendSlice("&digits=");
    try list.writer().print("{d}", .{digits});
    try list.appendSlice("&period=");
    try list.writer().print("{d}", .{period});
    return list.toOwnedSlice();
}

// RFC3548 base32
// input.len is gonna be 64 | 32 | 64
fn encodeBase32(list: *std.ArrayList(u8), input: []const u8) !void {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    var iter = BufBiterator.init(input);
    while (iter.nextInt(u5)) |idx| try list.append(alphabet[idx]);
}

const BufBiterator = struct {
    buf: []const u8,
    bits: std.bit_set.IntegerBitSet(8),
    idx: u8, // buf index
    jdx: u8, // bits index

    pub fn init(buf: []const u8) BufBiterator {
        return .{
            .buf = buf,
            .bits = .{ .mask = buf[0] },
            .idx = 0,
            .jdx = 0,
        };
    }

    pub fn nextInt(self: *BufBiterator, T: type) ?T {
        const info = @typeInfo(T).int;
        var result: T = 0;
        for (0..info.bits) |_| {
            result <<= 1;
            const val = self.next() orelse return null;
            result += val;
        }
        return result;
    }

    pub fn next(self: *BufBiterator) ?u1 {
        if (self.jdx == 8) {
            self.jdx = 0;
            self.idx += 1;
            if (self.idx == self.buf.len) return null;
            self.bits.mask = self.buf[self.idx];
            return self.next();
        }
        const result = self.bits.isSet(7 - self.jdx);
        self.jdx += 1;
        return @intFromBool(result);
    }
};
