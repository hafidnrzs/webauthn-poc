# WebAuthn Biometrik PoC

Login tanpa kata sandi pakai sidik jari / Face ID di browser HP.
Backend Go (`net/http` + `go-webauthn`), frontend HTML + JS biasa yang di-embed ke binary.

## Menjalankan

Butuh Go 1.26 atau lebih baru (syarat `go-webauthn` v0.18).

```bash
go mod tidy
RP_ORIGIN=http://localhost:8080 go run .
```

## Tes di HP

WebAuthn wajib HTTPS, dan domain harus sama dengan `RP_ORIGIN`.
Cara termudah adalah memakai tunnel HTTPS ke port 8080, lalu isi `RP_ORIGIN` dengan URL tunnel tersebut.

**Cloudflare Tunnel (tanpa akun):**
```bash
cloudflared tunnel --url http://localhost:8080
# salin URL https://xxxx.trycloudflare.com yang muncul
RP_ORIGIN=https://xxxx.trycloudflare.com go run .
```

**Tailscale (HP ikut tailnet):**
```bash
tailscale serve --bg 8080
RP_ORIGIN=https://nama-mesin.nama-tailnet.ts.net go run .
```

**ngrok:**
```bash
ngrok http 8080
RP_ORIGIN=https://xxxx.ngrok-free.app go run .
```

Buka URL tersebut di Safari (iOS) atau Chrome (Android), lalu:
1. Isi nama pengguna → **Daftarkan perangkat** → verifikasi biometrik.
2. Tekan **Masuk dengan biometrik** → pilih passkey → verifikasi.

## Catatan penting

- Passkey terikat ke domain. Kalau URL tunnel berubah (misalnya URL acak dari trycloudflare), passkey lama tidak bisa dipakai. Daftar ulang, dan hapus passkey lama dari pengaturan HP bila perlu.
- Data server disimpan di memori. Setelah restart, passkey di HP masih ada tetapi server sudah tidak mengenalnya, sehingga muncul pesan "passkey tidak dikenal".
- `userVerification: required` menjamin user terverifikasi, tetapi browser tidak memberi tahu *cara* verifikasinya. Di HP tanpa biometrik aktif, PIN atau pola layar juga dianggap sah.
- Untuk produksi, ganti penyimpanan in-memory dengan database dan simpan `webauthn.Credential` per user (termasuk `SignCount`).

## Struktur

```
main.go            server + endpoint WebAuthn
static/index.html  UI mobile (registrasi, login, cek dukungan, log teknis)
```

Endpoint: `POST /api/register/begin|finish`, `POST /api/login/begin|finish`, `GET /api/me`, `POST /api/logout`.
