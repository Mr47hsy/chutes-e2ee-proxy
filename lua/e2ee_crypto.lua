--
-- e2ee_crypto.lua - FFI bindings to libe2ee_proxy.so
--
-- Provides high-level Lua functions matching the Python transport's crypto module.
--

local ffi = require("ffi")
local ngx = ngx
local base64 = require("ngx.base64") or {
    encode_base64 = ngx.encode_base64,
    decode_base64 = ngx.decode_base64,
}
local cjson = require("cjson").new()
cjson.decode_array_with_array_mt(true)

ffi.cdef[[
    int e2ee_init(void);

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

local lib = ffi.load("/usr/local/openresty/lib/libe2ee_proxy.so")

local _M = {}

-- Constants matching Python transport
local MLKEM_CT_SIZE = 1088
local TAG_SIZE = 16
local INFO_REQ = "e2e-req-v1"
local INFO_RESP = "e2e-resp-v1"
local INFO_STREAM = "e2e-stream-v1"

-- Reusable buffers (sized for typical use)
local size_t_buf = ffi.new("size_t[1]")

--- Initialize the library. Call once at startup.
function _M.init()
    local rc = lib.e2ee_init()
    if rc ~= 0 then
        return nil, "e2ee_init failed (caller verification or anti-debug)"
    end
    return true
end

--- Get leaf certificate (DER bytes as lua string)
function _M.get_cert_der()
    local buf = ffi.new("uint8_t[8192]")
    size_t_buf[0] = 8192
    if lib.e2ee_get_cert_der(buf, size_t_buf) ~= 0 then
        return nil, "failed to get cert"
    end
    return ffi.string(buf, size_t_buf[0])
end

--- Get intermediate certificate (DER)
function _M.get_intermediate_der()
    local buf = ffi.new("uint8_t[8192]")
    size_t_buf[0] = 8192
    if lib.e2ee_get_intermediate_der(buf, size_t_buf) ~= 0 then
        return nil, "failed to get intermediate cert"
    end
    return ffi.string(buf, size_t_buf[0])
end

--- Get root certificate (DER)
function _M.get_root_der()
    local buf = ffi.new("uint8_t[8192]")
    size_t_buf[0] = 8192
    if lib.e2ee_get_root_der(buf, size_t_buf) ~= 0 then
        return nil, "failed to get root cert"
    end
    return ffi.string(buf, size_t_buf[0])
end

--- Get private key (DER)
function _M.get_privkey_der()
    local buf = ffi.new("uint8_t[8192]")
    size_t_buf[0] = 8192
    if lib.e2ee_get_privkey_der(buf, size_t_buf) ~= 0 then
        return nil, "failed to get private key"
    end
    return ffi.string(buf, size_t_buf[0])
end

--- Convert DER cert to PEM format
local function der_to_pem(der_bytes, label)
    label = label or "CERTIFICATE"
    local b64 = ngx.encode_base64(der_bytes)
    local lines = {}
    table.insert(lines, "-----BEGIN " .. label .. "-----")
    -- Split into 64-char lines
    for i = 1, #b64, 64 do
        table.insert(lines, b64:sub(i, i + 63))
    end
    table.insert(lines, "-----END " .. label .. "-----")
    return table.concat(lines, "\n") .. "\n"
end

--- Get full cert chain as concatenated DER (cert + intermediate + root)
--- This format is accepted by ngx.ssl.set_der_cert for chain support
function _M.get_cert_chain_der()
    local cert, err = _M.get_cert_der()
    if not cert then return nil, err end

    local intermediate
    intermediate, err = _M.get_intermediate_der()
    if not intermediate then return nil, err end

    local root
    root, err = _M.get_root_der()
    if not root then return nil, err end

    return cert .. intermediate .. root
end

--- Get full cert chain as PEM (cert + intermediate + root)
function _M.get_cert_chain_pem()
    local cert, err = _M.get_cert_der()
    if not cert then return nil, err end

    local intermediate
    intermediate, err = _M.get_intermediate_der()
    if not intermediate then return nil, err end

    local root
    root, err = _M.get_root_der()
    if not root then return nil, err end

    return der_to_pem(cert) .. der_to_pem(intermediate) .. der_to_pem(root)
end

--- Derive symmetric key using HKDF-SHA256
-- @param shared_secret  32-byte shared secret from ML-KEM
-- @param mlkem_ct       ML-KEM ciphertext (salt = first 16 bytes)
-- @param info           Context string (INFO_REQ, INFO_RESP, or INFO_STREAM)
-- @return 32-byte derived key
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

--- Build an encrypted E2EE request blob
-- @param e2e_pubkey_b64  Base64-encoded ML-KEM public key from instance discovery
-- @param payload_json    JSON string of the original request payload
-- @return blob (binary string), response_sk (binary string for decrypting response)
function _M.build_e2ee_request(e2e_pubkey_b64, payload_json)
    -- 1. Generate ephemeral keypair for response decryption
    local response_pk = ffi.new("uint8_t[1184]")
    local response_sk = ffi.new("uint8_t[2400]")
    if lib.e2ee_mlkem_keygen(response_pk, response_sk) ~= 0 then
        return nil, nil, "ML-KEM keygen failed"
    end

    -- 2. Decode server's public key
    local e2e_pubkey = ngx.decode_base64(e2e_pubkey_b64)
    if not e2e_pubkey or #e2e_pubkey ~= 1184 then
        return nil, nil, "invalid server pubkey"
    end

    -- 3. ML-KEM encapsulation with server's pubkey
    local mlkem_ct = ffi.new("uint8_t[1088]")
    local shared_secret = ffi.new("uint8_t[32]")
    if lib.e2ee_mlkem_encapsulate(
        ffi.cast("const uint8_t*", e2e_pubkey), mlkem_ct, shared_secret
    ) ~= 0 then
        return nil, nil, "ML-KEM encapsulation failed"
    end

    local mlkem_ct_str = ffi.string(mlkem_ct, 1088)
    local ss_str = ffi.string(shared_secret, 32)

    -- 4. Derive request encryption key
    local sym_key, err = derive_key(ss_str, mlkem_ct_str, INFO_REQ)
    if not sym_key then return nil, nil, err end

    -- 5. Augment payload with response public key
    local payload = cjson.decode(payload_json)
    payload["e2e_response_pk"] = ngx.encode_base64(ffi.string(response_pk, 1184))
    local augmented_json = cjson.encode(payload)

    -- 6. Gzip compress
    local compressed_buf = ffi.new("uint8_t[?]", #augmented_json + 1024)
    local compressed_len = lib.e2ee_gzip_compress(
        ffi.cast("const uint8_t*", augmented_json), #augmented_json,
        compressed_buf, #augmented_json + 1024
    )
    if compressed_len == 0 then
        return nil, nil, "gzip compression failed"
    end

    -- 7. Generate random nonce
    local nonce = ffi.new("uint8_t[12]")
    lib.e2ee_random_bytes(nonce, 12)

    -- 8. ChaCha20-Poly1305 encrypt
    local ciphertext = ffi.new("uint8_t[?]", compressed_len)
    local tag = ffi.new("uint8_t[16]")
    if lib.e2ee_chacha20_seal(
        ffi.cast("const uint8_t*", sym_key), nonce,
        compressed_buf, compressed_len,
        ciphertext, tag
    ) ~= 0 then
        return nil, nil, "encryption failed"
    end

    -- 9. Assemble blob: mlkem_ct(1088) + nonce(12) + ciphertext(N) + tag(16)
    local blob = mlkem_ct_str
             .. ffi.string(nonce, 12)
             .. ffi.string(ciphertext, compressed_len)
             .. ffi.string(tag, 16)

    return blob, ffi.string(response_sk, 2400)
end

--- Decrypt a non-streaming E2EE response
-- @param response_blob  Raw encrypted response bytes
-- @param response_sk    Client's ML-KEM secret key (from build_e2ee_request)
-- @return decrypted JSON string
function _M.decrypt_response(response_blob, response_sk)
    if #response_blob < MLKEM_CT_SIZE + 12 + TAG_SIZE then
        return nil, "response too short"
    end

    -- Parse blob
    local mlkem_ct = response_blob:sub(1, MLKEM_CT_SIZE)
    local nonce = response_blob:sub(MLKEM_CT_SIZE + 1, MLKEM_CT_SIZE + 12)
    local ciphertext = response_blob:sub(MLKEM_CT_SIZE + 13, #response_blob - TAG_SIZE)
    local tag = response_blob:sub(#response_blob - TAG_SIZE + 1)

    -- ML-KEM decapsulation
    local ss = ffi.new("uint8_t[32]")
    if lib.e2ee_mlkem_decapsulate(
        ffi.cast("const uint8_t*", response_sk),
        ffi.cast("const uint8_t*", mlkem_ct),
        ss
    ) ~= 0 then
        return nil, "ML-KEM decapsulation failed"
    end

    -- Derive response key
    local sym_key, err = derive_key(ffi.string(ss, 32), mlkem_ct, INFO_RESP)
    if not sym_key then return nil, err end

    -- Decrypt
    local ct_len = #ciphertext
    local plaintext = ffi.new("uint8_t[?]", ct_len)
    if lib.e2ee_chacha20_open(
        ffi.cast("const uint8_t*", sym_key),
        ffi.cast("const uint8_t*", nonce),
        ffi.cast("const uint8_t*", ciphertext), ct_len,
        ffi.cast("const uint8_t*", tag),
        plaintext
    ) ~= 0 then
        return nil, "decryption failed (auth tag mismatch)"
    end

    -- Decompress
    local decompressed_buf = ffi.new("uint8_t[?]", ct_len * 20 + 65536)
    local decompressed_len = lib.e2ee_gzip_decompress(
        plaintext, ct_len,
        decompressed_buf, ct_len * 20 + 65536
    )
    if decompressed_len == 0 then
        return nil, "gzip decompression failed"
    end

    return ffi.string(decompressed_buf, decompressed_len)
end

--- Decrypt the e2e_init event to get stream key
-- @param response_sk    Client's ML-KEM secret key
-- @param mlkem_ct_b64   Base64-encoded ML-KEM ciphertext from e2e_init event
-- @return 32-byte stream key
function _M.decrypt_stream_init(response_sk, mlkem_ct_b64)
    local mlkem_ct = ngx.decode_base64(mlkem_ct_b64)
    if not mlkem_ct or #mlkem_ct ~= MLKEM_CT_SIZE then
        return nil, "invalid e2e_init ciphertext"
    end

    local ss = ffi.new("uint8_t[32]")
    if lib.e2ee_mlkem_decapsulate(
        ffi.cast("const uint8_t*", response_sk),
        ffi.cast("const uint8_t*", mlkem_ct),
        ss
    ) ~= 0 then
        return nil, "stream init decapsulation failed"
    end

    return derive_key(ffi.string(ss, 32), mlkem_ct, INFO_STREAM)
end

--- Decrypt a single streaming chunk
-- @param enc_chunk_b64  Base64-encoded encrypted chunk
-- @param stream_key     32-byte stream key from decrypt_stream_init
-- @return decrypted string
function _M.decrypt_stream_chunk(enc_chunk_b64, stream_key)
    local raw = ngx.decode_base64(enc_chunk_b64)
    if not raw or #raw < 12 + TAG_SIZE then
        return nil, "invalid stream chunk"
    end

    local nonce = raw:sub(1, 12)
    local ciphertext = raw:sub(13, #raw - TAG_SIZE)
    local tag = raw:sub(#raw - TAG_SIZE + 1)
    local ct_len = #ciphertext

    local plaintext = ffi.new("uint8_t[?]", ct_len)
    if lib.e2ee_chacha20_open(
        ffi.cast("const uint8_t*", stream_key),
        ffi.cast("const uint8_t*", nonce),
        ffi.cast("const uint8_t*", ciphertext), ct_len,
        ffi.cast("const uint8_t*", tag),
        plaintext
    ) ~= 0 then
        return nil, "stream chunk decryption failed"
    end

    return ffi.string(plaintext, ct_len)
end

return _M
