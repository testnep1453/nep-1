# Firebase Setup Guide for NEP Gaming Hub

This guide will help you set up Firebase for the Pro-Gamer Student Hub application.

## Step 1: Create Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click "Add project"
3. Enter project name (e.g., "nep-gaming-hub")
4. Disable Google Analytics (optional)
5. Click "Create project"

## Step 2: Enable Required Services

### Firestore Database

1. In Firebase Console, click "Firestore Database"
2. Click "Create database"
3. Choose "Start in test mode" (for development)
4. Select a location close to your users
5. Click "Enable"

### Realtime Database

1. Click "Realtime Database" in the sidebar
2. Click "Create Database"
3. Choose "Start in test mode"
4. Click "Enable"

### Cloud Messaging

1. Click "Cloud Messaging" under "Engage"
2. It's automatically enabled for web apps
3. Generate Web Push certificate (VAPID key) in Project Settings > Cloud Messaging

## Step 3: Register Web App

1. In Project Overview, click the web icon `</>`
2. Register app nickname: "NEP Gaming Web"
3. Don't check "Firebase Hosting"
4. Click "Register app"
5. Copy the Firebase configuration object

## Step 4: Configure Environment Variables

Create a `.env` file in the project root:

```env
VITE_FIREBASE_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
VITE_FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=your-project-id
VITE_FIREBASE_STORAGE_BUCKET=your-project.appspot.com
VITE_FIREBASE_MESSAGING_SENDER_ID=123456789012
VITE_FIREBASE_APP_ID=1:123456789012:web:abcdef123456
VITE_FIREBASE_DATABASE_URL=https://your-project-default-rtdb.firebaseio.com
VITE_FIREBASE_VAPID_KEY=BNxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Step 5: Update Service Worker

Edit `public/firebase-messaging-sw.js` with your Firebase config:

```javascript
firebase.initializeApp({
  apiKey: "YOUR_API_KEY",
  authDomain: "your-project.firebaseapp.com",
  projectId: "your-project-id",
  storageBucket: "your-project.appspot.com",
  messagingSenderId: "123456789012",
  appId: "1:123456789012:web:abcdef123456"
});
```

## Step 6: Add Demo Data to Firestore

### Create Students Collection

In Firestore Console:

1. Click "Start collection"
2. Collection ID: `students`
3. Add documents with these IDs and fields:

**Document ID: `1234`**
```json
{
  "name": "LEGEND_WARRIOR",
  "xp": 2450,
  "level": 12,
  "badges": ["first_login", "week_streak", "quiz_master"],
  "avatar": "hero_cape_red",
  "lastSeen": [Current timestamp]
}
```

**Document ID: `5678`**
```json
{
  "name": "NINJA_MASTER",
  "xp": 1800,
  "level": 9,
  "badges": ["first_login", "fast_learner"],
  "avatar": "ninja_star",
  "lastSeen": [Current timestamp]
}
```

**Document ID: `9999`**
```json
{
  "name": "DRAGON_RIDER",
  "xp": 3200,
  "level": 16,
  "badges": ["first_login", "week_streak", "quiz_master", "perfect_score"],
  "avatar": "dragon_rider",
  "lastSeen": [Current timestamp]
}
```

### Create Lessons Collection

**Document ID: `nextLesson`**
```json
{
  "startTime": [Future timestamp - e.g., tomorrow at 2 PM],
  "title": "Matematik Savaşı",
  "zoomLink": "https://us06web.zoom.us/j/81331199971?pwd=wEBSZPJcBJg3MbV4FqGMO7ggJ3onM8.1"
}
```

To set a future timestamp in Firestore Console:
1. Click the clock icon next to the field
2. Select date and time
3. The format will be: `December 25, 2024 at 2:00:00 PM UTC+3`

## Step 7: Configure Firestore Security Rules

In Firestore Rules tab, add:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /students/{studentId} {
      allow read: if true;
      allow write: if false;
    }
    match /lessons/{lessonId} {
      allow read: if true;
      allow write: if false;
    }
  }
}
```

## Step 8: Configure Realtime Database Rules

In Realtime Database Rules tab, add:

```json
{
  "rules": {
    "presence": {
      "$uid": {
        ".write": true,
        ".read": true
      }
    }
  }
}
```

## Step 9: Test the Application

1. Run `npm install`
2. Run `npm run dev`
3. Open `http://localhost:5173`
4. Log in with student ID: `1234`, `5678`, or `9999`
5. Verify all features work:
   - Profile displays correctly
   - Countdown shows time remaining
   - Presence counter updates
   - Video theater works
   - Theme toggle functions

## Step 10: Deploy to Production

### Update Security Rules for Production

**Firestore Rules:**
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /students/{studentId} {
      allow read: if request.auth != null;
      allow write: if false;
    }
    match /lessons/{lessonId} {
      allow read: if request.auth != null;
      allow write: if false;
    }
  }
}
```

**Realtime Database Rules:**
```json
{
  "rules": {
    "presence": {
      "$uid": {
        ".write": true,
        ".read": true
      }
    }
  }
}
```

### Build and Deploy

```bash
npm run build
```

Upload the `dist` folder to your hosting provider.

## Troubleshooting

### Issue: "Firebase: Error (auth/configuration-not-found)"

**Solution:** Make sure all environment variables are set correctly in `.env`

### Issue: "Permission denied" in Firestore

**Solution:** Check your Firestore security rules allow read access

### Issue: Presence counter always shows 0

**Solution:**
1. Check Realtime Database is enabled
2. Verify database URL in `.env`
3. Check Realtime Database rules

### Issue: Notifications not working

**Solution:**
1. Check browser supports notifications
2. Verify VAPID key is correct
3. Allow notifications when prompted
4. Check `firebase-messaging-sw.js` is configured

## Adding New Students

To add new students, go to Firestore Console:

1. Open `students` collection
2. Click "Add document"
3. Enter student ID (e.g., "1111")
4. Add fields:
   - `name` (string): Student display name
   - `xp` (number): Starting XP (e.g., 0)
   - `level` (number): Starting level (e.g., 1)
   - `badges` (array): Starting badges (e.g., ["first_login"])
   - `avatar` (string): Avatar emoji key
   - `lastSeen` (timestamp): Current time
5. Click "Save"

## Updating Lesson Times

To schedule the next lesson:

1. Open Firestore Console
2. Navigate to `lessons/nextLesson`
3. Update `startTime` field to new date/time
4. Update `title` field with lesson name
5. Verify `zoomLink` is correct
6. Save changes

The countdown will automatically update for all logged-in students.

## Support

For issues or questions, contact your system administrator or check the main README.md file.
