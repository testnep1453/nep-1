# SECURITY_AUDIT.md — NEP Gaming

---

## [4-Haneli ID Brute-Force Saldırısı]
| Severity | Critical |
| Location | `StudentLogin.tsx`, `useAuth.ts` |
| The Exploit | Öğrenci ID'leri 3-4 haneli sayısal (100-9999). Sadece 10.000 kombinasyon var. `StudentLogin.tsx` her tuş vuruşunda otomatik giriş deniyor. Bir saldırgan 100'den başlayıp 9999'a kadar tüm numaratörü otomatik deneyerek tüm hesaplara girebilir. Rate limiting veya bloklama mekanizması yok. |
| The Fix | 1) 5 başarısız denemede 5 dakika bloke (localStorage `lastFailedAttempts` array'i ile). 2) 3 saniye minimum giriş bekleme süresi. 3) ID aralığını genişlet (6+ haneli) veya alfanümerik yap. 4) Admin tarafından verilen özel token sistemi. |

---

## [IDOR — Insecure Direct Object Reference]
| Severity | High |
| Location | `StudentLogin.tsx` + `useAuth.ts` |
| The Exploit | Öğrenci ID'leri bilinebilir veya tahmin edilebilir (örn: ardışık numaralar). ID'si bilinen herhangi bir öğrencinin hesabına giriş yapılabilir. Öğrenciler arasında veri izolasyonu yok — giriş yapan kişi başka öğrencinin XP, rozet, katılım geçmişini görebilir. |
| The Fix | 1) ID dışında ek doğrulama (örn: nickname + ID). 2) Her öğrenci için benzersiz token oluştur, girişte token + ID iste. 3) Admin onaylı ilk girişte şifre belirleme. |

---

## [Firestore Security Rules — Test Modu]
| Severity | Critical |
| Location | Firebase Console — Firestore + RTDB Kuralları |
| The Exploit | Kurallar `allow read, write: if true` ise: (a) Kötü niyetli biri tüm öğrenci listesini çeker, (b) tüm öğrencilerin XP/level verilerini sıfırlar, (c) sahte mesajlar gönderir, (d) fragman ayarlarını değiştirir. Veri bütünlüğü tamamen tehlikede. |
| The Fix | Firestore:
```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /students/{studentId} {
      allow read: if true;
      allow write: if request.auth != null;
    }
    match /messages/{messageId} {
      allow read: if true;
      allow write: if resource == null || request.resource.data.adminId == '1002';
    }
    match /settings/{settingId} {
      allow read: if true;
      allow write: if request.resource.data.adminId == '1002';
    }
    match /lessons/{lessonId} {
      allow read: if true;
      allow write: if request.auth != null;
    }
  }
}
```
RTDB:
```json
{
  "rules": {
    "presence": {
      "$uid": {
        ".write": "true",
        ".read": "true"
      }
    }
  }
}
```

---

## [localStorage — Tüm Öğrenci Listesi Açıkta]
| Severity | High |
| Location | `src/services/db.ts` |
| The Exploit | `db.ts` tüm öğrenci listesini `localStorage['studentdb']` içinde saklar. Herhangi bir öğrenci tarayıcı DevTools → Application → localStorage açıp tüm öğrencilerin ID, isim, nickname, XP, level verisini görebilir. Çocukların kişisel bilgileri (ad soyad) korumasız. |
| The Fix | localStorage'a SADECE giriş yapan öğrencinin session ID'si (`studentId`) yazılmalı. Öğrenci listesi localStorage'dan tamamen kaldırılmalı. Veriler sadece Firestore'dan `getDoc(doc(db, 'students', id))` ile çekilmeli. |

---

## [Firebase Config Bilgileri Açıkta]
| Severity | Info (Düşük) |
| Location | `src/config/firebase.ts`, `public/firebase-messaging-sw.js` |
| The Exploit | API key, authDomain, projectId gibi bilgiler kaynak kodunda açık. Bu bilgiler tarayıcıda çalışan her uygulamada zorunludur ve gizlenemez. Risk, API key'in kötüye kullanımı değildir — kuralların zayıf olmasıdır. |
| The Fix | API key gizli DEĞİL, kurallarla korunmalı. Firebase Console'da kuralları sıkılaştır. Ayrıca Firebase API Key Restrictions ayarında sadece kendi domain'iniz için izin verin. `firebase-messaging-sw.js` placeholder'larını `.env` ile build sonrası doldurun. |

---

## [XSS Riski — YouTube iframe Injection]
| Severity | Medium |
| Location | `YouTubePlayer.tsx` — `videoId` prop |
| The Exploit | `videoId` admin tarafından kontrol ediliyor ama gelecekte başka bir kaynaktan gelirse, `https://www.youtube.com/embed/${videoId}` ile kötü amaçlı içerik yüklenebilir. YouTube embed URL validasyonu yok. |
| The Fix | `videoId` regex validasyonu: `/^[a-zA-Z0-9_-]{11}$/`. Geçersiz ID durumunda render'ı engelle. |

---

## [Zoom Link Manipülasyonu]
| Severity | Low |
| Location | `JoinClassButton.tsx` — `studentName` base64 encode |
| The Exploit | `btoa(unescape(encodeURIComponent(studentName)))` doğru ama studentName localStorage'dan geliyor. Öğrenci kendi ismini manipüle edip Zoom linkine ek parametre enjekte edebilir. |
| The Fix | studentName'i sanitize et — sadece alphanumeric + boşluk karakterlere izin ver. |
