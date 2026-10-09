# RoomKhojo Backend (API)

Express 5 + Mongoose + Cloudinary. JWT auth (user + admin), Google Sign-In verify, Email-OTP password reset.

## Setup

```bash
npm install
cp .env.example .env   # values bharo
npm run dev            # nodemon src/server.js
```

## Env vars

`.env.example` dekho. Zaroori: `MONGO_URI`, `JWT_SECRET`, `GOOGLE_CLIENT_ID`, `CLOUDINARY_*`, `FRONTEND_URL`. OTP emails ke liye `SMTP_*`.

## API

| Method | Endpoint | Auth | Kaam |
|---|---|---|---|
| GET | `/` | — | Health check |
| GET | `/api/rooms` | — | Live rooms (map) |
| POST | `/api/rooms` | User | Naya ad (photo upload) |
| GET | `/api/rooms/user/:userId` | Self/Admin | Apne ads |
| PUT | `/api/rooms/:id/edit` | Owner/Admin | Edit → dobara pending |
| PATCH | `/api/rooms/:id/toggle-status` | Owner/Admin | Hide/Show |
| PATCH | `/api/rooms/:id/approve` | Admin | Approve (+promo unlock) |
| DELETE | `/api/rooms/:id` | Owner/Admin | Delete |
| PUT | `/api/rooms/:id/report-unavailable` | — | Report (1 IP = 1 report) |
| POST | `/api/users/signup` | — | Email signup → JWT |
| POST | `/api/users/login` | — | Email login → JWT |
| POST | `/api/users/google` | — | Google idToken verify → JWT |
| POST | `/api/users/forgot-password` | — | OTP email |
| POST | `/api/users/verify-otp` | — | OTP → reset token |
| POST | `/api/users/reset-password` | — | Naya password |
| POST | `/api/users/change-password` | User | Password change |
| GET | `/api/users/count` | Admin | Users count |
| POST | `/api/admin/login` | — | Admin login → JWT (12h) |
| POST | `/api/admin/change-credentials` | Admin | Username/password change |
| GET | `/api/admin/settings` | — | Categories/facilities/pricing |
| POST | `/api/admin/settings` | Admin | Settings update |
| GET | `/api/rooms/admin/all` | Admin | Saare ads |

Auth header: `Authorization: Bearer <token>`

## Deploy (Vercel)

- Entry: `api/index.js` + `vercel.json` rewrites (serverless).
- Vercel dashboard me saare env vars set karo (`.env.example` list).
- Pehla admin DB khaali hone par `ADMIN_INITIAL_*` se banta hai — login karke turant password badal lena.
- Password bhool jao toh: `ADMIN_FORCE_RESET=true` + naya `ADMIN_INITIAL_PASSWORD` → redeploy → login → flag hatao → redeploy.
