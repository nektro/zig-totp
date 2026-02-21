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
