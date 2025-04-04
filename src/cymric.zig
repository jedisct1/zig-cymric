const std = @import("std");

pub const key_bytes = 16;
pub const nonce_bytes = 12;
pub const block_bytes = 16;
pub const tag_bytes = 16;

pub const AesRoundkeys = struct {
    enc_ctx: std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes128),

    pub fn init(key: []const u8) AesRoundkeys {
        var key_array: [key_bytes]u8 = undefined;
        @memcpy(&key_array, key[0..key_bytes]);
        return .{
            .enc_ctx = std.crypto.core.aes.Aes128.initEnc(key_array),
        };
    }

    pub fn encrypt(self: *const AesRoundkeys, out: []u8, block: *const [block_bytes]u8) void {
        self.enc_ctx.encrypt(out[0..block_bytes], block);
    }
};

pub const CipherCtx = struct {
    roundkeys: *AesRoundkeys,
};

pub const Error = error{
    InvalidInputLength,
    AuthenticationFailed,
};

inline fn xor(dst: []u8, a: []const u8, b: []const u8) void {
    std.debug.assert(dst.len == a.len and a.len == b.len);
    for (dst, a, b) |*d, x, y| d.* = x ^ y;
}

/// Authenticated encryption using Cymric1
///
/// Encrypts a message using the Cymric1 authenticated encryption scheme.
///
/// Parameters:
///   - out: Output buffer for the encrypted message (ciphertext)
///   - tag: Output buffer for the authentication tag
///   - msg: Input message to encrypt
///   - ad: Associated data (not encrypted but authenticated)
///   - nonce: Nonce value (must be unique for each encryption with the same key)
///   - key: Encryption key
///   - ctx: Cipher context containing the encryption functions and round keys
pub fn cymric1_encrypt(
    out: []u8,
    tag: []u8,
    msg: []const u8,
    ad: []const u8,
    nonce: []const u8,
    key: []const u8,
    ctx: CipherCtx,
) Error!void {
    // Check inputs' validity first to avoid unnecessary work
    if (msg.len + nonce.len > block_bytes) return Error.InvalidInputLength;
    if (nonce.len + ad.len > block_bytes - 1) return Error.InvalidInputLength;

    // Prepare aligned buffers for better performance
    var tmp_buffer: [2 * block_bytes]u8 align(16) = [_]u8{0} ** (2 * block_bytes);
    const y0 = tmp_buffer[block_bytes..];
    const y1 = tmp_buffer[0..block_bytes];

    // Determine if |N|+|M|== n
    const b = if (msg.len + nonce.len == block_bytes) @as(u8, 1 << 7) else 0;

    // Initialize the AES context with the key
    ctx.roundkeys.* = AesRoundkeys.init(key);

    // Prepare the first block: Y0 <- E_K(padn(N||A||b0))
    var block: [block_bytes]u8 align(16) = [_]u8{0} ** block_bytes;
    @memcpy(block[0..nonce.len], nonce);
    @memcpy(block[nonce.len .. nonce.len + ad.len], ad);
    block[nonce.len + ad.len] = b | 0x20;

    // Encrypt with AES
    ctx.roundkeys.encrypt(y0, &block);

    // Prepare the second block: Y1 <- E_K(padn(N||A||b1))
    block[nonce.len + ad.len] = b | 0x60; // Set both bits in one operation

    // Encrypt with AES
    ctx.roundkeys.encrypt(y1, &block);

    // C <- M ^ Y0 ^ Y1 (optimize for common case of small messages)
    var y0y1_xor: [block_bytes]u8 align(16) = undefined;
    xor(&y0y1_xor, y0[0..block_bytes], y1[0..block_bytes]);

    // Optimize for small messages by avoiding loop overhead
    if (msg.len <= 16) {
        inline for (0..16) |i| {
            if (i < msg.len) out[i] = msg[i] ^ y0y1_xor[i];
        }
    } else {
        for (0..msg.len) |i| {
            out[i] = msg[i] ^ y0y1_xor[i];
        }
    }

    // T <- E_K'(N||M||pad ^ Y0)
    @memset(&block, 0);
    @memcpy(block[0..nonce.len], nonce);
    @memcpy(block[nonce.len .. nonce.len + msg.len], msg);

    if (nonce.len + msg.len != block_bytes) {
        block[nonce.len + msg.len] = 0x80;
    }

    // XOR with Y0 directly
    xor(&block, &block, y0[0..block_bytes]);

    // T = msb(E_K'(T))
    // Initialize with the second key and encrypt
    ctx.roundkeys.* = AesRoundkeys.init(key[key_bytes..]);
    ctx.roundkeys.encrypt(tmp_buffer[0..block_bytes], &block);

    @memcpy(tag[0..tag_bytes], tmp_buffer[0..tag_bytes]);
}

/// Authenticated decryption using Cymric1
///
/// Decrypts a message using the Cymric1 authenticated encryption scheme.
///
/// Parameters:
///   - out: Output buffer for the decrypted message (plaintext)
///   - cipher: Input ciphertext to decrypt
///   - tag: Authentication tag to verify
///   - ad: Associated data (not encrypted but authenticated)
///   - nonce: Nonce value (must be the same as used for encryption)
///   - key: Encryption key
///   - ctx: Cipher context containing the encryption functions and round keys
///
/// Returns:
///   - Error.AuthenticationFailed if the tag verification fails
pub fn cymric1_decrypt(
    out: []u8,
    cipher: []const u8,
    tag: []const u8,
    ad: []const u8,
    nonce: []const u8,
    key: []const u8,
    ctx: CipherCtx,
) Error!void {
    // Check inputs' validity first to avoid unnecessary work
    if (cipher.len + nonce.len > block_bytes) return Error.InvalidInputLength;
    if (nonce.len + ad.len > block_bytes - 1) return Error.InvalidInputLength;

    // Prepare aligned buffers for better performance
    var tmp_buffer: [2 * block_bytes]u8 align(16) = [_]u8{0} ** (2 * block_bytes);
    const y0 = tmp_buffer[block_bytes..];
    const y1 = tmp_buffer[0..block_bytes];
    var tag_computed: [tag_bytes]u8 align(16) = [_]u8{0} ** tag_bytes;

    // Determine if |N|+|C|== n
    const b = if (cipher.len + nonce.len == block_bytes) @as(u8, 1 << 7) else 0;

    // Initialize the AES context with the key
    ctx.roundkeys.* = AesRoundkeys.init(key);

    // Prepare the first block: Y0 <- E_K(padn(N||A||b0))
    var block: [block_bytes]u8 align(16) = [_]u8{0} ** block_bytes;
    @memcpy(block[0..nonce.len], nonce);
    @memcpy(block[nonce.len .. nonce.len + ad.len], ad);
    block[nonce.len + ad.len] = b | 0x20;

    // Encrypt with AES
    ctx.roundkeys.encrypt(y0, &block);

    // Prepare the second block: Y1 <- E_K(padn(N||A||b1))
    block[nonce.len + ad.len] = b | 0x60; // Set both bits in one operation

    // Encrypt with AES
    ctx.roundkeys.encrypt(y1, &block);

    // M <- C ^ Y0 ^ Y1 (optimize for common case of small messages)
    var y0y1_xor: [block_bytes]u8 align(16) = undefined;
    xor(&y0y1_xor, y0[0..block_bytes], y1[0..block_bytes]);

    // Optimize for small ciphertexts by avoiding loop overhead
    if (cipher.len <= 16) {
        inline for (0..16) |i| {
            if (i < cipher.len) out[i] = cipher[i] ^ y0y1_xor[i];
        }
    } else {
        for (0..cipher.len) |i| {
            out[i] = cipher[i] ^ y0y1_xor[i];
        }
    }

    // T <- E_K'(N||M||pad ^ Y0)
    @memset(&block, 0);
    @memcpy(block[0..nonce.len], nonce);
    @memcpy(block[nonce.len .. nonce.len + cipher.len], out[0..cipher.len]);

    if (nonce.len + cipher.len != block_bytes) {
        block[nonce.len + cipher.len] = 0x80;
    }

    // XOR with Y0 directly
    xor(&block, &block, y0[0..block_bytes]);

    // T = msb(E_K'(T))
    // Initialize with the second key and encrypt
    ctx.roundkeys.* = AesRoundkeys.init(key[key_bytes..]);
    ctx.roundkeys.encrypt(&tag_computed, &block);

    // Verify tag using constant-time comparison
    if (!std.crypto.timing_safe.eql([tag_bytes]u8, tag_computed, tag[0..tag_bytes].*)) {
        // If tags don't match, zero out the output
        @memset(out[0..cipher.len], 0);
        return Error.AuthenticationFailed;
    }
}

/// Authenticated encryption using Cymric2
///
/// Encrypts a message using the Cymric2 authenticated encryption scheme.
///
/// Parameters:
///   - out: Output buffer for the encrypted message (ciphertext)
///   - tag: Output buffer for the authentication tag
///   - msg: Input message to encrypt
///   - ad: Associated data (not encrypted but authenticated)
///   - nonce: Nonce value (must be unique for each encryption with the same key)
///   - key: Encryption key
///   - ctx: Cipher context containing the encryption functions and round keys
pub fn cymric2_encrypt(
    out: []u8,
    tag: []u8,
    msg: []const u8,
    ad: []const u8,
    nonce: []const u8,
    key: []const u8,
    ctx: CipherCtx,
) Error!void {
    // Check inputs' validity first to avoid unnecessary work
    if (msg.len > block_bytes) return Error.InvalidInputLength;
    if (nonce.len + ad.len > block_bytes - 1) return Error.InvalidInputLength;

    // Prepare aligned buffers for better performance
    var tmp_buffer: [2 * block_bytes]u8 align(16) = [_]u8{0} ** (2 * block_bytes);
    const y0 = tmp_buffer[block_bytes..];
    const y1 = tmp_buffer[0..block_bytes];

    // Determine if |M|== n
    const b = if (msg.len == block_bytes) @as(u8, 1 << 7) else 0;

    // Initialize the AES context with the key
    ctx.roundkeys.* = AesRoundkeys.init(key);

    // Prepare the first block: Y0 <- E_K(padn(N||A||b0))
    var block: [block_bytes]u8 align(16) = [_]u8{0} ** block_bytes;
    @memcpy(block[0..nonce.len], nonce);
    @memcpy(block[nonce.len .. nonce.len + ad.len], ad);
    block[nonce.len + ad.len] = b | 0x20;

    // Encrypt with AES
    ctx.roundkeys.encrypt(y0, &block);

    // Prepare the second block: Y1 <- E_K(padn(N||A||b1))
    block[nonce.len + ad.len] = b | 0x60; // Set both bits in one operation

    // Encrypt with AES
    ctx.roundkeys.encrypt(y1, &block);

    // C <- M ^ Y0 ^ Y1 (optimize for common case of small messages)
    var y0y1_xor: [block_bytes]u8 align(16) = undefined;
    xor(&y0y1_xor, y0[0..block_bytes], y1[0..block_bytes]);

    // Optimize for small messages by avoiding loop overhead
    if (msg.len <= 16) {
        inline for (0..16) |i| {
            if (i < msg.len) out[i] = msg[i] ^ y0y1_xor[i];
        }
    } else {
        for (0..msg.len) |i| {
            out[i] = msg[i] ^ y0y1_xor[i];
        }
    }

    // T <- Y0 ^ pad(M)
    @memset(&block, 0);
    @memcpy(block[0..msg.len], msg);

    if (msg.len != block_bytes) {
        block[msg.len] = 0x80;
    }

    // XOR with Y0 directly
    xor(&block, &block, y0[0..block_bytes]);

    // T = msb(E_K'(T))
    // Initialize with the second key and encrypt
    ctx.roundkeys.* = AesRoundkeys.init(key[key_bytes..]);
    ctx.roundkeys.encrypt(tmp_buffer[0..block_bytes], &block);

    @memcpy(tag[0..tag_bytes], tmp_buffer[0..tag_bytes]);
}

/// Authenticated decryption using Cymric2
///
/// Decrypts a message using the Cymric2 authenticated encryption scheme.
///
/// Parameters:
///   - out: Output buffer for the decrypted message (plaintext)
///   - cipher: Input ciphertext to decrypt
///   - tag: Authentication tag to verify
///   - ad: Associated data (not encrypted but authenticated)
///   - nonce: Nonce value (must be the same as used for encryption)
///   - key: Encryption key
///   - ctx: Cipher context containing the encryption functions and round keys
///
/// Returns:
///   - Error.AuthenticationFailed if the tag verification fails
pub fn cymric2_decrypt(
    out: []u8,
    cipher: []const u8,
    tag: []const u8,
    ad: []const u8,
    nonce: []const u8,
    key: []const u8,
    ctx: CipherCtx,
) Error!void {
    // Check inputs' validity first to avoid unnecessary work
    if (cipher.len > block_bytes) return Error.InvalidInputLength;
    if (nonce.len + ad.len > block_bytes - 1) return Error.InvalidInputLength;

    // Prepare aligned buffers for better performance
    var tmp_buffer: [2 * block_bytes]u8 align(16) = [_]u8{0} ** (2 * block_bytes);
    const y0 = tmp_buffer[block_bytes..];
    const y1 = tmp_buffer[0..block_bytes];
    var tag_computed: [tag_bytes]u8 align(16) = [_]u8{0} ** tag_bytes;

    // Determine if |C|== n
    const b = if (cipher.len == block_bytes) @as(u8, 1 << 7) else 0;

    // Initialize the AES context with the key
    ctx.roundkeys.* = AesRoundkeys.init(key);

    // Prepare the first block: Y0 <- E_K(padn(N||A||b0))
    var block: [block_bytes]u8 align(16) = [_]u8{0} ** block_bytes;
    @memcpy(block[0..nonce.len], nonce);
    @memcpy(block[nonce.len .. nonce.len + ad.len], ad);
    block[nonce.len + ad.len] = b | 0x20;

    // Encrypt with AES
    ctx.roundkeys.encrypt(y0, &block);

    // Prepare the second block: Y1 <- E_K(padn(N||A||b1))
    block[nonce.len + ad.len] = b | 0x60; // Set both bits in one operation

    // Encrypt with AES
    ctx.roundkeys.encrypt(y1, &block);

    // M <- C ^ Y0 ^ Y1 (optimize for common case of small messages)
    var y0y1_xor: [block_bytes]u8 align(16) = undefined;
    xor(&y0y1_xor, y0[0..block_bytes], y1[0..block_bytes]);

    // Optimize for small ciphertexts by avoiding loop overhead
    if (cipher.len <= 16) {
        inline for (0..16) |i| {
            if (i < cipher.len) out[i] = cipher[i] ^ y0y1_xor[i];
        }
    } else {
        for (0..cipher.len) |i| {
            out[i] = cipher[i] ^ y0y1_xor[i];
        }
    }

    // T <- Y0 ^ pad(M)
    @memset(&block, 0);
    @memcpy(block[0..cipher.len], out[0..cipher.len]);

    if (cipher.len != block_bytes) {
        block[cipher.len] = 0x80;
    }

    // XOR with Y0 directly
    xor(&block, &block, y0[0..block_bytes]);

    // T = msb(E_K'(T))
    // Initialize with the second key and encrypt
    ctx.roundkeys.* = AesRoundkeys.init(key[key_bytes..]);
    ctx.roundkeys.encrypt(&tag_computed, &block);

    // Verify tag using constant-time comparison
    if (!std.crypto.timing_safe.eql([tag_bytes]u8, tag_computed, tag[0..tag_bytes].*)) {
        // If tags don't match, zero out the output
        @memset(out[0..cipher.len], 0);
        return Error.AuthenticationFailed;
    }
}
