// TLS plaintext capture at the SSPI layer (the classic Frida "SSL_write/SSL_read" recipe,
// Windows flavour: hook EncryptMessage / DecryptMessage, which every SChannel client --
// curl.exe, WinHTTP, .NET, browsers' system TLS -- goes through).
//
//   sspicli!EncryptMessage entry   the SECBUFFER_DATA buffers hold the PLAINTEXT about to
//                                  be encrypted in place: log it
//   sspicli!DecryptMessage entry   the data is still ciphertext: remember the
//                                  SecBufferDesc under the return-site SP, probe the site
//   <call site> (return)           SEC_E_OK -> the DATA buffer now points at plaintext
#include "../common/famous_common.h"

namespace {
constexpr uint32_t kSecBufferData = 1;
constexpr size_t kMaxShown = 384;     // bytes of plaintext per log line
} // namespace

UHH_SHARED famous_site g_tls_sites[8]{};
UHH_SHARED famous_pending g_tls_pending[32]{};
UHH_SHARED std::atomic<int64_t> g_tls_unmatched{0};

// SecBufferDesc { ULONG ulVersion; ULONG cBuffers; PSecBuffer pBuffers; }
// SecBuffer     { ULONG cbBuffer; ULONG BufferType; PVOID pvBuffer; }  (12 / 16 bytes)
static void log_data_buffers(probe_context *c, const char *op, uint64_t desc, uint32_t status) {
    uint32_t head[2] = {0, 0};
    if (!desc || !get_mem(c, desc, head, sizeof(head))) return;
    uint64_t buffers = famous_read_ptr(c, desc + 8);
    const uint64_t stride = 8 + famous_ptr;
    for (uint32_t i = 0; i < head[1] && i < 8; ++i) {
        uint32_t meta[2] = {0, 0};
        if (!get_mem(c, buffers + i * stride, meta, sizeof(meta))) return;
        if ((meta[1] & 0x0fffffff) != kSecBufferData || meta[0] == 0) continue;
        uint64_t data = famous_read_ptr(c, buffers + i * stride + 8);
        uint8_t bytes[kMaxShown];
        size_t n = meta[0] < kMaxShown ? meta[0] : kMaxShown;
        if (!get_mem(c, data, bytes, n)) continue;
        char text[kMaxShown * 4 + 1];
        famous_escape(bytes, n, text, sizeof(text));
        send_log(c, "tls-%s status=0x%08x len=%u data=%s", op, status, meta[0], text);
    }
}

FAMOUS_EXPORT void famous_tls_on_decrypt_return(probe_context *c) {
    uint64_t desc = 0, unused = 0;
    if (!famous_pending_take(g_tls_pending, 32, get_reg(c, PROBE_REG_SP), desc, unused)) {
        g_tls_unmatched.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    uint32_t status = (uint32_t)get_reg(c, PROBE_REG_AX);
    if (status == 0) log_data_buffers(c, "decrypt", desc, status);   // SEC_E_OK
}

// DecryptMessage(PCtxtHandle, PSecBufferDesc, ULONG MessageSeqNo, PULONG pfQOP)
FAMOUS_EXPORT void famous_tls_on_decrypt(probe_context *c) {
    uint64_t ret = famous_return_address(c);
    if (famous_pending_put(g_tls_pending, 32, famous_return_sp(c, 4), get_func_arg(c, 1), 0))
        famous_arm_return(c, g_tls_sites, 8, ret, famous_tls_on_decrypt_return, famous_ret_flags(c));
}

// EncryptMessage(PCtxtHandle, ULONG fQOP, PSecBufferDesc, ULONG MessageSeqNo)
FAMOUS_EXPORT void famous_tls_on_encrypt(probe_context *c) {
    log_data_buffers(c, "encrypt", get_func_arg(c, 2), 0);
}
