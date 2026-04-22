# NEP Pro-Gamer Student Hub

A gaming-themed educational platform for 9-10 year old students featuring countdown timers, real-time presence tracking, XP/level system, and Zoom class integration.

## Features

- **Student Authentication**: Simple numeric ID login (3-4 digits)
- **Circular SVG Countdown**: Gaming-style countdown to next class
- **Join Class Flow**: Terminal animation sequence before Zoom redirect
- **Real-time Presence**: Firebase Realtime Database for online student counter
- **Profile Dashboard**: Avatar, XP, level, badges system
- **Video Theater**: YouTube embed with emoji reactions
- **Firebase Cloud Messaging**: Push notifications for class reminders
- **Dark/Light Theme**: Toggle between themes

## Tech Stack

- React 18 + TypeScript
- Vite
- Tailwind CSS
- Firebase SDK v10+
  - Firestore (student data, lessons)
  - Realtime Database (presence tracking)
  - Cloud Messaging (notifications)
- Lucide React (icons)
- Canvas Confetti (badge unlocks)

## Firebase Setup

### 1. Create Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create a new project
3. Enable the following services:
   - Firestore Database
   - Realtime Database
   - Cloud Messaging

### 2. Get Configuration

1. In Project Settings, find your Firebase config
2. Copy to `.env` file (see `.env.example`)

### 3. Firestore Setup

Create a `students` collection with documents like:

```javascript
// Document ID: "1234" (student ID)
{
  name: "LEGEND_WARRIOR",
  xp: 2450,
  level: 12,
  badges: ["first_login", "week_streak", "quiz_master"],
  avatar: "hero_cape_red",
  lastSeen: Timestamp
}
```

Create a `lessons` collection:

```javascript
// Document ID: "nextLesson"
{
  startTime: Timestamp, // e.g., new Date("2024-01-15T14:00:00")
  title: "Matematik Savaşı",
  zoomLink: "https://us06web.zoom.us/j/81331199971?pwd=..."
}
```

### 4. Realtime Database Rules

```json
{
  "rules": {
    "presence": {
      "$uid": {
        ".write": "$uid === auth.uid",
        ".read": true
      }
    }
  }
}
```

### 5. Cloud Messaging Setup

1. In Project Settings > Cloud Messaging
2. Generate a new Web Push certificate (VAPID key)
3. Add to `.env` as `VITE_FIREBASE_VAPID_KEY`
4. Update `public/firebase-messaging-sw.js` with your Firebase config

### 6. Environment Variables

Copy `.env.example` to `.env` and fill in your Firebase credentials:

```env
VITE_FIREBASE_API_KEY=your_api_key
VITE_FIREBASE_AUTH_DOMAIN=your_project.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=your_project_id
VITE_FIREBASE_STORAGE_BUCKET=your_project.appspot.com
VITE_FIREBASE_MESSAGING_SENDER_ID=123456789
VITE_FIREBASE_APP_ID=1:123456789:web:abc123
VITE_FIREBASE_DATABASE_URL=https://your_project-default-rtdb.firebaseio.com
VITE_FIREBASE_VAPID_KEY=your_vapid_key
```

## Installation

```bash
npm install
```

## Development

```bash
npm run dev
```

## Build

```bash
npm run build
```

## Usage

### Student Login

Students log in with their numeric ID (e.g., "1234"). The ID must exist in the Firestore `students` collection.

### Countdown System

The app displays a circular countdown to the next lesson. When the countdown reaches zero, a glowing "DERSE KATIL" button appears.

### Join Class Flow

1. Click "DERSE KATIL" button
2. Terminal animation shows connection sequence
3. Auto-redirect to Zoom with student name encoded in URL

### Presence System

When a student logs in, they appear in the online counter. This uses Firebase Realtime Database with automatic disconnect handling.

## Customization

### Avatars

Edit `AVATAR_EMOJIS` in `src/components/Dashboard/ProfileSection.tsx`:

```typescript
const AVATAR_EMOJIS: Record<string, string> = {
  hero_cape_red: '🦸‍♂️',
  warrior_sword: '⚔️',
  // Add more...
};
```

### Badges

Edit `BADGE_INFO` in `src/components/Dashboard/ProfileSection.tsx`:

```typescript
const BADGE_INFO: Record<string, { emoji: string; name: string }> = {
  first_login: { emoji: '🎮', name: 'İlk Giriş' },
  // Add more...
};
```

### Colors

The gaming color palette is defined in the components:

- Primary: `#6358cc` (purple)
- Success: `#2b9956` (green)
- Danger: `#d44d4e` (red)
- Warning: `#ff9f43` (orange)
- Info: `#00cfe8` (cyan)

## Project Structure

```
src/
├── components/
│   ├── Auth/
│   │   └── StudentLogin.tsx
│   ├── Countdown/
│   │   ├── CircularCountdown.tsx
│   │   └── JoinClassButton.tsx
│   ├── Dashboard/
│   │   ├── ProfileSection.tsx
│   │   ├── PresenceCounter.tsx
│   │   ├── NotificationBell.tsx
│   │   └── ThemeToggle.tsx
│   └── VideoTheater/
│       └── YouTubePlayer.tsx
├── hooks/
│   ├── useAuth.ts
│   ├── useCountdown.ts
│   └── usePresence.ts
├── services/
│   └── fcm.ts
├── types/
│   └── student.ts
├── config/
│   └── firebase.ts
└── App.tsx
```

## Security Notes

- Student IDs are persistent in localStorage
- No logout functionality (by design)
- Firebase rules should restrict write access
- Only authenticated students should access data

## License

Private educational project for NEP Education Center.
Son Güncelleme: Artifact hatası çözümü için temiz kurulum tetiklemesi.