# TLS plaintext capture (SSPI / SChannel)

## The original recipe

On OpenSSL targets the classic Frida script hooks `SSL_write` (plaintext at entry) and
`SSL_read` (plaintext at `onLeave`). Windows' system TLS is SChannel behind SSPI, so the
Windows flavour (used against curl, WinHTTP/WinINet, .NET, ...) is:

```js
const sspi = 'sspicli.dll';
Interceptor.attach(Module.getExportByName(sspi, 'EncryptMessage'), {
  onEnter(args) { dumpDataBuffers(args[2]); }                     // plaintext, about to be encrypted
});
Interceptor.attach(Module.getExportByName(sspi, 'DecryptMessage'), {
  onEnter(args) { this.desc = args[1]; },
  onLeave(status) { if (status.toInt32() === 0) dumpDataBuffers(this.desc); }   // decrypted in place
});
```

`secur32.dll`'s exports forward to `sspicli.dll`, and the function table SChannel clients
get from `InitSecurityInterfaceW` points there too, so `sspicli` is where to hook.

## UHH mapping (`tls_callbacks.cpp`)

| Frida | UHH |
|---|---|
| `EncryptMessage` `onEnter` | `famous_tls_on_encrypt`: `SecBufferDesc` (arg 2) -> each `SECBUFFER_DATA` buffer -> `get_mem` -> `tls-encrypt len= data=` |
| `DecryptMessage` `onEnter` | `famous_tls_on_decrypt`: keep the `SecBufferDesc` (arg 1) under the return-site SP, arm the call site |
| `onLeave` | `famous_tls_on_decrypt_return`: `SEC_E_OK` in `AX` -> the DATA buffer now points at plaintext -> `tls-decrypt` |
| `hexdump` | `famous_escape` (printable ASCII, `\xNN` otherwise; first 384 bytes per buffer) |

`SecBufferDesc {ULONG ver; ULONG count; PSecBuffer p}` has `pBuffers` at +8 on both
architectures; `SecBuffer {ULONG cb; ULONG type; PVOID pv}` is 12 bytes on x86 and 16 on x64.

## Fully offline setup

- Client: the real `C:\Windows\System32\curl.exe` (SysWOW64 for x86), built on SChannel,
  shipped with Windows 10 1803+. `-k --ssl-no-revoke` because the server cert is self-signed
  and there is no network for revocation checks.
- Server: `tls_server.py` -- Python's `ssl` + `http.server` on `127.0.0.1` with the throwaway
  self-signed test certificate in `fixtures/` (CN=localhost; test-only key, committed on
  purpose). The response body carries a marker and echoes the request path and header.

```powershell
python examples\famous\tls_capture\tls_server.py          # prints {"port": P}
famous_driver --recipe tls --backend inline -- C:\Windows\System32\curl.exe -s -k --ssl-no-revoke `
    -H "X-UHH: request-marker-91c2" https://127.0.0.1:P/uhh-secret-path?token=s3cr3t
```

Expected: a `tls-encrypt` line containing `GET /uhh-secret-path?token=s3cr3t HTTP/1.1` and the
`X-UHH` header, a `tls-decrypt` line containing `UHH-TLS-RESPONSE-MARKER-7f3a`, and curl's
output identical to the uninstrumented run -- on every backend.
