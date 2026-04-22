# AGENTS.md — NEP Gaming Project

Bu dosya, bu projeyle çalışan AI ajanları için kesin kılavuzdur. Her kural bu projeye özgüdür.

---

## Proje Tanımı

NEP Gaming, 8-10 yaş öğrenciler için haftalık NEP ders platformudur. Vite + React + TypeScript + Tailwind + Firebase kullanır. Öğrenciler 3-4 haneli sayısal ID ile giriş yapar. "Ajan/hacker" teması kullanılmıştır: neon yeşil (#39FF14), cyan (#00F0FF), mor (#6358cc), turuncu (#FF4500).

---

## Firebase Yapılandırması

**Dosya:** `src/config/firebase.ts`

| Değişken | Amaç |
|---|---|
| `db` (Firestore) | Öğrenci verileri, mesajlar, fragman ayarları, ders bilgileri |
| `rtdb` (RTDB) | Online sayaç (presence) |
| `auth` | Hazır ama kullanılmıyor — giriş sayısal ID ile yapılıyor |
| `messaging` | FCM push bildirimleri |

**ÖNEMLİ:** `.env` dosyası `.gitignore`'da. Build ortamında `.env` olmadan Firebase demo-project ile sahte değerlere düşer ve `ERR_BLOCKED_BY_CLIENT`/`offline` hataları verir.

### Firebase Collections

| Collection | Belge ID | İçerik |
|---|---|---|
| `students/{id}` | Öğrenci ID | name, nickname, xp, level, badges, avatar, lastSeen, attendanceHistory, streak |
| `messages/{autoId}` | Firebase otomatik | text, date (realtime admin duyuruları) |
| `lessons/nextLesson` | Sabit | startTime, title, zoomLink |
| `settings/trailer` | Sabit | youtubeId, showDate, showTime, isActive |

### RTDB Yapısı

| Path | İçerik |
|---|---|
| `presence/{studentId}` | true/false (online durumu) |

---

## Veri Akışı Mimarisi

1. **Giriş:** `StudentLogin.tsx` → `useAuth.ts` → önce localStorage (`db.ts`), sonra Firestore (`dbFirebase.ts`)
2. **Geçiş:** `App.tsx` → 5 saniye `LoginTransitionOverlay` → `UnifiedDashboard`
3. **Dashboard:** 4 sekmeli yan menü — Genel Durum, Operasyon, Ajan Yönetimi (admin), Mesajlar (admin)
4. **Admin:** student.id === `1002`. Öğrenci ekleme/silme, fragman yönetimi, mesaj gönderme, toplu Excel yükleme

### Çift Veri Katmanı

- `db.ts` → localStorage tabanlı "simüle" veritabanı. `studentdb` key'i altında tüm öğrenciler.
- `dbFirebase.ts` → Firestore tabanlı gerçek veritabanı.
- `useAuth` önce localStorage'a bakar, bulamazsa Firestore'a düşer.

---

## Tailwind Kuralları

### Proje Renkleri

| Hex | Kullanım |
|---|---|
| `#39FF14` | Yeşil neon — admin vurguları, başarı |
| `#00F0FF` | Cyan — öğrenci vurguları |
| `#6358cc` | Mor — kartlar, progress bar |
| `#FF4500` | Turuncu — uyarılar, rozetler |
| `#050505` | Siyah — arka plan |
| `#0A1128` | Koyu lacivert — kart arka planları |

### Özel Animasyonlar (`index.css`)

| Animasyon | Property | Kullanım |
|---|---|---|
| `animate-typing` | width animation | Giriş ekranı başlık yazma efekti |
| `animate-rocket-launch` | transform + opacity | Roket fırlatma geçişi |
| `animate-eyes-closing` | opacity + backdrop-filter | Karartma efekti |
| `animate-glow-pulse` | box-shadow animation | Derse katıl butonu |
| `animate-float-up` | transform + opacity | Emoji reaksiyonlar |
| `animate-terminal-line` | transform + opacity | Terminal satır animasyonu |

### Özel Sınıflar

- `.clip-path-diagonal` — Köşegen kesme efekti (kartlar)
- `.scanlines` — CRT tarama çizgisi efekti
- `.terminal-scroll` — Terminal içi scroll

---

## Geçiş Efektleri

**Dosya:** `src/components/Transitions/LoginTransitionOverlay.tsx`

1. Roket fırlatma (1.5sn, 🚀 emoji büyüyüp kayboluyor)
2. Göz kapama efekti (siyah arka plan, "Işınlanıyorsunuz!" metni)
3. Toplam süre: 5sn (`App.tsx`'de `setTimeout`)

---

## Bileşen Hiyerarşisi

```
App.tsx
├── loading → "YÜKLENİYOR..."
├── loggingIn → StudentLogin.tsx
├── loginSuccessTransition → LoginTransitionOverlay.tsx
└── dashboard → UnifiedDashboard.tsx
    ├── ProfileSection (öğrenci profili, XP, rozetler)
    ├── PresenceCounter (çevrimiçi sayacı)
    ├── MessageFeed (admin duyuruları)
    ├── CircularCountdown (geri sayım)
    ├── JoinClassButton (Zoom yönlendirme + terminal)
    ├── YouTubePlayer (fragman/media)
    └── Admin paneli (1002)
```

---

## Vite Yapılandırması

**Dosya:** `vite.config.ts`

- `base: '/nep1/'` — GitHub Pages deployment için zorunlu
- `server.hmr.overlay: false` — Hata overlay'i kapalı
- `optimizeDeps.exclude: ['lucide-react']` — Lucide optimize dışı
- `clearScreen: false` — Server başlatırken ekran temizleme kapalı

---

## StudentLogin Davranışı

- 3-4 haneli sayısal ID girişi
- Her onChange → `getStudents()` localStorage'dan okuyor (PERFORMANS SORUNU, bak: OPTIMIZATIONS.md)
- 3 hane eşleşirse otomatik giriş
- 3 hane kısmi eşleşme → console.warn(admin bildirim)
- Placeholder'da rastgele ID "typing" efekti

---

## Admin Yetkileri

Admin ID: `1002`

- Öğrenci ekleme (tek tek + toplu Excel ile)
- Öğrenci silme
- XP ekleme (manuel, otomatik sistemle birlikte)
- Mesaj gönderme (Firestore `messages` collection)
- Fragman yönetimi (YouTube linki + gün/saat + aktif/pasif)
- 3+ hafta devamsız öğrencileri tespit etme + özel mesaj gönderme

---

## Kritik Kurallar

1. **Asla** `firebase-messaging-sw.js` içindeki placeholder API key'leri silme — bunlar build sırasında `.env` değerleriyle doldurulmalı.
2. **Asla** `base: '/nep1/'`'i Vite config'den kaldırma — GitHub Pages kırılır.
3. **Asla** Firestore kurallarını `allow read, write: if true` bırakma — SECURITY_AUDIT.md'ye bak.
4. **Her zaman** `studentId` localStorage'dan okurken hata durumunda `undefined` dön, null değil.
5. **Her zaman** `usePresence` null studentId durumunda erken dönüş yapar.
