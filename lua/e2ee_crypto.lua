--
-- e2ee_crypto.lua - FFI bindings to libe2ee_proxy.so
--
-- Wire format (must match the Chutes instance; see README "E2EE protocol"):
--   request blob   mlkem_ct(1088) || nonce(12) || ciphertext(N) || tag(16)
--   response blob  same layout
--   stream chunk   base64(nonce(12) || ciphertext || tag(16))
--   KDF            HKDF-SHA256(ikm=shared_secret, salt=mlkem_ct[0:16], info)
--   AEAD           ChaCha20-Poly1305, no AAD
--   compression    gzip, before encryption
--

local ffi = require("ffi")
local ngx = ngx
local bit = require("bit")
local config = require("e2ee_config")
local cjson = require("cjson").new()
cjson.decode_array_with_array_mt(true)

ffi.cdef[[
    int e2ee_init(void);
    const char *e2ee_build_info(void);

    int e2ee_get_cert_der(uint8_t *out, size_t *len);
    int e2ee_get_intermediate_der(uint8_t *out, size_t *len);
    int e2ee_get_root_der(uint8_t *out, size_t *len);
    int e2ee_get_privkey_der(uint8_t *out, size_t *len);

    int e2ee_mlkem_keygen(uint8_t *pk, uint8_t *sk);
    int e2ee_mlkem_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss);
    int e2ee_mlkem_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss);

    int e2ee_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                         const uint8_t *salt, size_t salt_len,
                         const uint8_t *info, size_t info_len,
                         uint8_t *okm, size_t okm_len);

    int e2ee_chacha20_seal(const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t *plaintext, size_t pt_len,
                           uint8_t *ciphertext, uint8_t tag[16]);

    int e2ee_chacha20_open(const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t *ciphertext, size_t ct_len,
                           const uint8_t tag[16], uint8_t *plaintext);

    size_t e2ee_gzip_compress(const uint8_t *in, size_t in_len,
                              uint8_t *out, size_t out_max);
    size_t e2ee_gzip_decompress(const uint8_t *in, size_t in_len,
                                uint8_t *out, size_t out_max);

    void e2ee_random_bytes(uint8_t *out, size_t len);
]]

local lib = ffi.load(config.E2EE_LIB_PATH)

local _M = {}

-- Constants matching the Chutes transport
local MLKEM_PK_SIZE = 1184
local MLKEM_SK_SIZE = 2400
local MLKEM_CT_SIZE = 1088
local NONCE_SIZE = 12
local TAG_SIZE = 16
local INFO_REQ = "e2e-req-v1"
local INFO_RESP = "e2e-resp-v1"
local INFO_STREAM = "e2e-stream-v1"

-- Gzip output can exceed input for incompressible data (e.g. base64 images).
-- This mirrors zlib's deflateBound() plus gzip framing, so a single-shot
-- deflate never runs out of room.
local function gzip_bound(n)
    return n + bit.rshift(n, 12) + bit.rshift(n, 14) + bit.rshift(n, 25) + 64
end

-- gzip trailer carries ISIZE = uncompressed length mod 2^32 (RFC 1952).
-- Reads the last four bytes of a uint8_t buffer without copying it.
local function gzip_isize(buf, n)
    if n < 18 then
        return nil
    end
    return buf[n - 4] + buf[n - 3] * 256 + buf[n - 2] * 65536 + buf[n - 1] * 16777216
end

--- Initialize the library. Call once at worker startup.
function _M.init()
    local rc = lib.e2ee_init()
    if rc ~= 0 then
        return nil, "e2ee_init returned " .. tostring(rc)
    end
    return true
end

function _M.build_info()
    local ok, s = pcall(function()
        return ffi.string(lib.e2ee_build_info())
    end)
    if ok then
        return s
    end
    return "unknown"
end

--- Derive a symmetric key with HKDF-SHA256.
-- @param shared_secret  32-byte ML-KEM shared secret
-- @param mlkem_ct       ML-KEM ciphertext; salt = first 16 bytes
-- @param info           INFO_REQ / INFO_RESP / INFO_STREAM
local function derive_key(shared_secret, mlkem_ct, info)
    local okm = ffi.new("uint8_t[32]")
    local salt = ffi.new("uint8_t[16]")
    ffi.copy(salt, mlkem_ct, 16)

    local rc = lib.e2ee_hkdf_sha256(
        ffi.cast("const uint8_t*", shared_secret), #shared_secret,
        salt, 16,
        ffi.cast("const uint8_t*", info), #info,
        okm, 32
    )
    if rc ~= 0 then
        return nil, "HKDF derivation failed"
    end
    return ffi.string(okm, 32)
end

--- Build an encrypted E2EE request blob.
-- @param e2e_pubkey_b64  base64 ML-KEM public key from instance discovery
-- @param payload_json    JSON string of the client request
-- @return blob, response_sk   (or nil, nil, err)
function _M.build_e2ee_request(e2e_pubkey_b64, payload_json)
    -- 1. Ephemeral keypair; the instance encrypts its response to this key.
    local response_pk = ffi.new("uint8_t[?]", MLKEM_PK_SIZE)
    local response_sk = ffi.new("uint8_t[?]", MLKEM_SK_SIZE)
    if lib.e2ee_mlkem_keygen(response_pk, response_sk) ~= 0 then
        return nil, nil, "ML-KEM keygen failed"
    end

    -- 2. Instance public key
    local e2e_pubkey = ngx.decode_base64(e2e_pubkey_b64 or "")
    if not e2e_pubkey or #e2e_pubkey ~= MLKEM_PK_SIZE then
        return nil, nil, "invalid server pubkey (expected " .. MLKEM_PK_SIZE .. " bytes)"
    end

    -- 3. Encapsulate
    local mlkem_ct = ffi.new("uint8_t[?]", MLKEM_CT_SIZE)
    local shared_secret = ffi.new("uint8_t[32]")
    if lib.e2ee_mlkem_encapsulate(ffi.cast("const uint8_t*", e2e_pubkey), mlkem_ct, shared_secret) ~= 0 then
        return nil, nil, "ML-KEM encapsulation failed"
    end
    local mlkem_ct_str = ffi.string(mlkem_ct, MLKEM_CT_SIZE)
    local ss_str = ffi.string(shared_secret, 32)

    -- 4. Request key
    local sym_key, err = derive_key(ss_str, mlkem_ct_str, INFO_REQ)
    if not sym_key then
        return nil, nil, err
    end

    -- 5. Inject the response public key into the payload
    local payload = cjson.decode(payload_json)
    if type(payload) ~= "table" then
        return nil, nil, "payload is not a JSON object"
    end
    payload["e2e_response_pk"] = ngx.encode_base64(ffi.string(response_pk, MLKEM_PK_SIZE))
    local augmented_json = cjson.encode(payload)

    -- 6. Gzip
    local in_len = #augmented_json
    local bound = gzip_bound(in_len)
    local compressed_buf = ffi.new("uint8_t[?]", bound)
    local compressed_len = tonumber(lib.e2ee_gzip_compress(
        ffi.cast("const uint8_t*", augmented_json), in_len, compressed_buf, bound))
    if compressed_len == 0 then
        return nil, nil, "gzip compression failed"
    end

    -- 7. Nonce
    local nonce = ffi.new("uint8_t[12]")
    lib.e2ee_random_bytes(nonce, NONCE_SIZE)

    -- 8. Seal
    local ciphertext = ffi.new("uint8_t[?]", compressed_len)
    local tag = ffi.new("uint8_t[16]")
    if lib.e2ee_chacha20_seal(ffi.cast("const uint8_t*", sym_key), nonce,
                              compressed_buf, compressed_len, ciphertext, tag) ~= 0 then
        return nil, nil, "encryption failed"
    end

    -- 9. Assemble
    local blob = mlkem_ct_str
        .. ffi.string(nonce, NONCE_SIZE)
        .. ffi.string(ciphertext, compressed_len)
        .. ffi.string(tag, TAG_SIZE)

    return blob, ffi.string(response_sk, MLKEM_SK_SIZE)
end

--- Decrypt a non-streaming response blob.
-- @param response_blob  raw bytes from upstream
-- @param response_sk    ML-KEM secret key from build_e2ee_request
-- @return plaintext JSON string
function _M.decrypt_response(response_blob, response_sk)
    if #response_blob < MLKEM_CT_SIZE + NONCE_SIZE + TAG_SIZE then
        return nil, "response too short"
    end

    local mlkem_ct = response_blob:sub(1, MLKEM_CT_SIZE)
    local nonce = response_blob:sub(MLKEM_CT_SIZE + 1, MLKEM_CT_SIZE + NONCE_SIZE)
    local ciphertext = response_blob:sub(MLKEM_CT_SIZE + NONCE_SIZE + 1, #response_blob - TAG_SIZE)
    local tag = response_blob:sub(#response_blob - TAG_SIZE + 1)

    local ss = ffi.new("uint8_t[32]")
    if lib.e2ee_mlkem_decapsulate(ffi.cast("const uint8_t*", response_sk),
                                  ffi.cast("const uint8_t*", mlkem_ct), ss) ~= 0 then
        return nil, "ML-KEM decapsulation failed"
    end

    local sym_key, err = derive_key(ffi.string(ss, 32), mlkem_ct, INFO_RESP)
    if not sym_key then
        return nil, err
    end

    local ct_len = #ciphertext
    local plaintext = ffi.new("uint8_t[?]", ct_len > 0 and ct_len or 1)
    if lib.e2ee_chacha20_open(ffi.cast("const uint8_t*", sym_key), ffi.cast("const uint8_t*", nonce),
                              ffi.cast("const uint8_t*", ciphertext), ct_len,
                              ffi.cast("const uint8_t*", tag), plaintext) ~= 0 then
        return nil, "decryption failed (auth tag mismatch)"
    end

    -- Size the output from the gzip ISIZE trailer instead of guessing a ratio.
    local isize = gzip_isize(plaintext, ct_len)
    if not isize or isize == 0 then
        return nil, "decrypted payload is not gzip"
    end
    local out_max = isize + 1
    local decompressed_buf = ffi.new("uint8_t[?]", out_max)
    local decompressed_len = tonumber(lib.e2ee_gzip_decompress(plaintext, ct_len, decompressed_buf, out_max))
    if decompressed_len == 0 then
        return nil, "gzip decompression failed"
    end

    return ffi.string(decompressed_buf, decompressed_len)
end

--- Derive the stream key from the e2e_init event.
-- @param response_sk    ML-KEM secret key
-- @param mlkem_ct_b64   base64 ML-KEM ciphertext from the e2e_init event
-- @return 32-byte stream key
function _M.decrypt_stream_init(response_sk, mlkem_ct_b64)
    local mlkem_ct = ngx.decode_base64(mlkem_ct_b64 or "")
    if not mlkem_ct or #mlkem_ct ~= MLKEM_CT_SIZE then
        return nil, "invalid e2e_init ciphertext"
    end

    local ss = ffi.new("uint8_t[32]")
    if lib.e2ee_mlkem_decapsulate(ffi.cast("const uint8_t*", response_sk),
                                  ffi.cast("const uint8_t*", mlkem_ct), ss) ~= 0 then
        return nil, "stream init decapsulation failed"
    end

    return derive_key(ffi.string(ss, 32), mlkem_ct, INFO_STREAM)
end

--- Decrypt one streaming chunk.
-- @param enc_chunk_b64  base64(nonce || ciphertext || tag)
-- @param stream_key     from decrypt_stream_init
function _M.decrypt_stream_chunk(enc_chunk_b64, stream_key)
    local raw = ngx.decode_base64(enc_chunk_b64 or "")
    if not raw or #raw < NONCE_SIZE + TAG_SIZE then
        return nil, "invalid stream chunk"
    end

    local nonce = raw:sub(1, NONCE_SIZE)
    local ciphertext = raw:sub(NONCE_SIZE + 1, #raw - TAG_SIZE)
    local tag = raw:sub(#raw - TAG_SIZE + 1)
    local ct_len = #ciphertext

    local plaintext = ffi.new("uint8_t[?]", ct_len > 0 and ct_len or 1)
    if lib.e2ee_chacha20_open(ffi.cast("const uint8_t*", stream_key), ffi.cast("const uint8_t*", nonce),
                              ffi.cast("const uint8_t*", ciphertext), ct_len,
                              ffi.cast("const uint8_t*", tag), plaintext) ~= 0 then
        return nil, "stream chunk decryption failed"
    end

    return ffi.string(plaintext, ct_len)
end

return _M
