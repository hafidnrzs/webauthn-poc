// WebAuthn biometric PoC — satu binary Go, frontend di-embed.
//
// Jalankan:
//
//	RP_ORIGIN=https://nama-tunnel-kamu.example.com go run .
//
// RP_ORIGIN harus sama persis dengan URL yang dibuka di browser HP
// (skema + host, tanpa path). RP ID diambil dari host-nya.
// Semua data disimpan di memori: restart server = passkey di server hilang.
package main

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

//go:embed static
var staticFiles embed.FS

// ---------- User (mengimplementasikan webauthn.User) ----------

type User struct {
	ID          []byte
	Name        string
	Credentials []webauthn.Credential
}

func (u *User) WebAuthnID() []byte                         { return u.ID }
func (u *User) WebAuthnName() string                       { return u.Name }
func (u *User) WebAuthnDisplayName() string                { return u.Name }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// ---------- Penyimpanan in-memory (cukup untuk PoC) ----------

type ceremony struct {
	session *webauthn.SessionData
	user    *User // hanya terisi saat registrasi
}

type Store struct {
	mu         sync.Mutex
	usersByKey map[string]*User    // username -> user
	usersByID  map[string]*User    // user handle -> user
	ceremonies map[string]ceremony // cookie wa_ceremony -> challenge yang sedang berjalan
	logins     map[string]string   // cookie wa_login -> username
}

func NewStore() *Store {
	return &Store{
		usersByKey: map[string]*User{},
		usersByID:  map[string]*User{},
		ceremonies: map[string]ceremony{},
		logins:     map[string]string{},
	}
}

// ---------- Server ----------

type Server struct {
	wa     *webauthn.WebAuthn
	store  *Store
	secure bool
}

func main() {
	origin := getenv("RP_ORIGIN", "http://localhost:8080")
	port := getenv("PORT", "8080")

	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		log.Fatalf("RP_ORIGIN tidak valid: %q", origin)
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "Biometrik PoC",
		RPOrigins:     []string{origin},
	})
	if err != nil {
		log.Fatal(err)
	}

	s := &Server{wa: wa, store: NewStore(), secure: u.Scheme == "https"}

	static, _ := fs.Sub(staticFiles, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServer(http.FS(static)))
	mux.HandleFunc("POST /api/register/begin", s.registerBegin)
	mux.HandleFunc("POST /api/register/finish", s.registerFinish)
	mux.HandleFunc("POST /api/login/begin", s.loginBegin)
	mux.HandleFunc("POST /api/login/finish", s.loginFinish)
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("POST /api/logout", s.logout)

	log.Printf("RP ID: %s | origin: %s | listen :%s", u.Hostname(), origin, port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

// ---------- Registrasi ----------

func (s *Server) registerBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Username == "" {
		log.Printf("[daftar 1/3] ditolak: nama pengguna kosong")
		writeErr(w, http.StatusBadRequest, "Isi nama pengguna dulu.")
		return
	}

	s.store.mu.Lock()
	user, exists := s.store.usersByKey[body.Username]
	s.store.mu.Unlock()
	if !exists {
		user = &User{ID: randomBytes(32), Name: body.Username}
	}

	// Cegah authenticator yang sama didaftarkan dua kali untuk user ini.
	var exclude []protocol.CredentialDescriptor
	for _, c := range user.Credentials {
		exclude = append(exclude, c.Descriptor())
	}

	creation, session, err := s.wa.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.Platform,                       // sensor bawaan HP, bukan security key
			ResidentKey:             protocol.ResidentKeyRequirementRequired, // passkey: login tanpa ketik username
			UserVerification:        protocol.VerificationRequired,           // wajib verifikasi (biometrik / kunci layar)
		}),
		webauthn.WithExclusions(exclude),
	)
	if err != nil {
		log.Printf("[daftar 1/3] gagal membuat tantangan untuk %q: %v", body.Username, err)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	log.Printf("[daftar 1/3] tantangan dikirim ke %q (user baru: %t, passkey lama: %d); menunggu HP membuat passkey",
		body.Username, !exists, len(user.Credentials))
	s.startCeremony(w, ceremony{session: session, user: user})
	writeJSON(w, creation)
}

func (s *Server) registerFinish(w http.ResponseWriter, r *http.Request) {
	c, ok := s.takeCeremony(w, r)
	if !ok || c.user == nil {
		log.Printf("[daftar 3/3] ditolak: sesi registrasi tidak ada atau kedaluwarsa")
		writeErr(w, http.StatusBadRequest, "Sesi registrasi tidak ditemukan atau kedaluwarsa. Ulangi dari awal.")
		return
	}

	cred, err := s.wa.FinishRegistration(c.user, *c.session, r)
	if err != nil {
		log.Printf("[daftar 3/3] gagal untuk %q: %s", c.user.Name, describe(err))
		writeErr(w, http.StatusBadRequest, "Verifikasi registrasi gagal: "+describe(err))
		return
	}

	s.store.mu.Lock()
	c.user.Credentials = append(c.user.Credentials, *cred)
	s.store.usersByKey[c.user.Name] = c.user
	s.store.usersByID[string(c.user.ID)] = c.user
	passkeys := len(c.user.Credentials)
	s.store.mu.Unlock()

	log.Printf("[daftar 3/3] berhasil: %q, credential %s, UV=%t, dicadangkan=%t, transport=%v, total passkey=%d",
		c.user.Name, short(cred.ID), cred.Flags.UserVerified, cred.Flags.BackupState, cred.Transport, passkeys)

	writeJSON(w, map[string]any{
		"username":     c.user.Name,
		"credentialId": b64(cred.ID),
		"userVerified": cred.Flags.UserVerified,
		"backedUp":     cred.Flags.BackupState,
		"transports":   cred.Transport,
	})
}

// ---------- Login (discoverable / passkey) ----------

func (s *Server) loginBegin(w http.ResponseWriter, r *http.Request) {
	assertion, session, err := s.wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		log.Printf("[masuk 1/3] gagal membuat tantangan: %v", err)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("[masuk 1/3] tantangan dikirim; menunggu HP menandatangani")
	s.startCeremony(w, ceremony{session: session})
	writeJSON(w, assertion)
}

func (s *Server) loginFinish(w http.ResponseWriter, r *http.Request) {
	c, ok := s.takeCeremony(w, r)
	if !ok {
		log.Printf("[masuk 3/3] ditolak: sesi login tidak ada atau kedaluwarsa")
		writeErr(w, http.StatusBadRequest, "Sesi login tidak ditemukan atau kedaluwarsa. Ulangi dari awal.")
		return
	}

	// Dipanggil library untuk mencari user berdasarkan userHandle dari authenticator.
	findUser := func(rawID, userHandle []byte) (webauthn.User, error) {
		s.store.mu.Lock()
		defer s.store.mu.Unlock()
		if u, ok := s.store.usersByID[string(userHandle)]; ok {
			return u, nil
		}
		return nil, errors.New("passkey ini tidak dikenal server (mungkin server sudah di-restart)")
	}

	wu, cred, err := s.wa.FinishPasskeyLogin(findUser, *c.session, r)
	if err != nil {
		log.Printf("[masuk 3/3] gagal: %s", describe(err))
		writeErr(w, http.StatusUnauthorized, "Login gagal: "+describe(err))
		return
	}
	user := wu.(*User)

	// Simpan sign counter terbaru (untuk deteksi authenticator hasil kloning).
	s.store.mu.Lock()
	for i := range user.Credentials {
		if string(user.Credentials[i].ID) == string(cred.ID) {
			user.Credentials[i].Authenticator = cred.Authenticator
		}
	}
	token := b64(randomBytes(32))
	s.store.logins[token] = user.Name
	passkeys := len(user.Credentials)
	s.store.mu.Unlock()

	log.Printf("[masuk 3/3] berhasil: %q, credential %s, UV=%t, sign count=%d",
		user.Name, short(cred.ID), cred.Flags.UserVerified, cred.Authenticator.SignCount)

	http.SetCookie(w, s.cookie("wa_login", token, 24*time.Hour))
	writeJSON(w, map[string]any{
		"username":     user.Name,
		"credentialId": b64(cred.ID),
		"userVerified": cred.Flags.UserVerified,
		"signCount":    cred.Authenticator.SignCount,
		"passkeys":     passkeys,
	})
}

// ---------- Sesi aplikasi ----------

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie("wa_login")
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "Belum masuk.")
		return
	}
	s.store.mu.Lock()
	name, ok := s.store.logins[ck.Value]
	count := 0
	if u := s.store.usersByKey[name]; u != nil {
		count = len(u.Credentials)
	}
	s.store.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Belum masuk.")
		return
	}
	writeJSON(w, map[string]any{"username": name, "passkeys": count})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie("wa_login"); err == nil {
		s.store.mu.Lock()
		if name, ok := s.store.logins[ck.Value]; ok {
			log.Printf("[keluar] %q", name)
		}
		delete(s.store.logins, ck.Value)
		s.store.mu.Unlock()
	}
	http.SetCookie(w, s.cookie("wa_login", "", -time.Hour))
	writeJSON(w, map[string]bool{"ok": true})
}

// ---------- Helper ----------

func (s *Server) startCeremony(w http.ResponseWriter, c ceremony) {
	id := b64(randomBytes(24))
	s.store.mu.Lock()
	s.store.ceremonies[id] = c
	s.store.mu.Unlock()
	http.SetCookie(w, s.cookie("wa_ceremony", id, 5*time.Minute))
}

// takeCeremony mengambil sekaligus menghapus challenge supaya tidak bisa dipakai ulang.
func (s *Server) takeCeremony(w http.ResponseWriter, r *http.Request) (ceremony, bool) {
	ck, err := r.Cookie("wa_ceremony")
	if err != nil {
		return ceremony{}, false
	}
	s.store.mu.Lock()
	c, ok := s.store.ceremonies[ck.Value]
	delete(s.store.ceremonies, ck.Value)
	s.store.mu.Unlock()
	http.SetCookie(w, s.cookie("wa_ceremony", "", -time.Hour))
	return c, ok
}

func (s *Server) cookie(name, value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  time.Now().Add(ttl),
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// describe menampilkan detail error dari library agar mudah di-debug saat PoC.
func describe(err error) string {
	var perr *protocol.Error
	if errors.As(err, &perr) && perr.DevInfo != "" {
		return perr.Details + " (" + perr.DevInfo + ")"
	}
	return err.Error()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// short memotong credential ID supaya log tetap terbaca.
func short(id []byte) string {
	s := b64(id)
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
