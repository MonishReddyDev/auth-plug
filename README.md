# Auth-Plug

**Auth-Plug** is a Node.js authentication and authorization service built with Express, Passport, and JWT.  
It supports user registration, email/password login, JWT-based authentication, role-based access, and OAuth2 social logins via GitHub and Google.  
API documentation is provided via Swagger (OpenAPI).

---

## 🚀 Features

- User registration and login (email/password)
- JWT access & refresh tokens
- Role-based authorization (`ADMIN`, `USER`, etc.)
- Email verification via OTP
- Forgot/reset password via OTP
- Social login (GitHub and Google OAuth)
- Secure HTTP cookies for refresh tokens
- API documentation with Swagger UI

---

## 🏗️ Tech Stack

- [Node.js](https://nodejs.org/)
- [Express](https://expressjs.com/)
- [Passport.js](http://www.passportjs.org/) (Local, GitHub, Google strategies)
- [JWT](https://jwt.io/) (jsonwebtoken)
- [Swagger UI](https://swagger.io/tools/swagger-ui/)
- [dotenv](https://www.npmjs.com/package/dotenv)
- [helmet](https://helmetjs.github.io/)
- [morgan](https://www.npmjs.com/package/morgan)
- [cookie-parser](https://www.npmjs.com/package/cookie-parser)
- [CORS](https://www.npmjs.com/package/cors)

---

## 📑 API Documentation

- Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)  
  (or `/api/auth/docs` if your route is set up that way)
- OpenAPI spec: [`openapi.yaml`](./openapi.yaml)

---

## 🛠️ Getting Started

### 1. **Clone the repo**

```bash
git clone https://github.com/MonishReddyDev/auth-plug.git
cd auth-plug
```

### 2. **Install dependencies**

```bash
npm install
```

### 3. **Environment variables**

Create a `.env` file in the root directory. Example:

```
PORT=8000
JWT_SECRET=your_jwt_secret
JWT_REFRESH_SECRET=your_refresh_secret
MONGO_URI=mongodb://localhost:27017/auth-plug
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
BASE_URL=http://localhost:8000
FRONTEND_URL=http://localhost:3000
```

> **Note:** Set up your OAuth credentials with GitHub and Google and update the IDs/secrets.

### 4. **Run the server**

```bash
npm start
```

---

## 🌐 API Endpoints (Summary)

- `POST /api/auth/register` — Register user (email, password, role)
- `POST /api/auth/login` — Login (email, password)
- `POST /api/auth/refresh` — Refresh JWT tokens via cookie
- `POST /api/auth/logout` — Logout current session
- `POST /api/auth/logoutAll` — Logout all sessions
- `POST /api/auth/verify-otp` — Email verification (OTP)
- `POST /api/auth/resend-otp` — Resend verification OTP
- `POST /api/auth/forgotPassword` — Request reset password OTP
- `POST /api/auth/resetPassword` — Reset password with OTP
- `GET /api/auth/github` — Start GitHub OAuth2 login
- `GET /api/auth/github/callback` — GitHub OAuth2 callback
- `GET /api/auth/google` — Start Google OAuth2 login
- `GET /api/auth/google/callback` — Google OAuth2 callback

See [openapi.yaml](./openapi.yaml) or `/docs` for full details.

---

## ✨ Social Auth Setup

- Register your app with [GitHub Developer Settings](https://github.com/settings/developers) and [Google Cloud Console](https://console.cloud.google.com/apis/credentials) to get OAuth client IDs/secrets.
- Set valid callback URLs, e.g.:
  - `http://localhost:8000/api/auth/github/callback`
  - `http://localhost:8000/api/auth/google/callback`

---

## 🛡️ Security Notes

- Always use strong secrets in production (`JWT_SECRET`, etc).
- Set CORS and cookie options securely for production.
- HTTPS is recommended for all deployments.

---

## 📝 License

MIT

---

## 👤 Author

- [MonishReddyDev](https://github.com/MonishReddyDev)
