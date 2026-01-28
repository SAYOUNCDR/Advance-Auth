# Advance Auth

![TypeScript](https://img.shields.io/badge/typescript-%23007ACC.svg?style=flat&logo=typescript&logoColor=white)
![NodeJS](https://img.shields.io/badge/node.js-6DA55F?style=flat&logo=node.js&logoColor=white)
![Express.js](https://img.shields.io/badge/express.js-%23404d59.svg?style=flat&logo=express&logoColor=%2361DAFB)
![MongoDB](https://img.shields.io/badge/MongoDB-%234ea94b.svg?style=flat&logo=mongodb&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-black?style=flat&logo=JSON%20web%20tokens)
![Zod](https://img.shields.io/badge/zod-%233068b7.svg?style=flat&logo=zod&logoColor=white)

> **A robust, production-ready authentication template built with Node.js, Express, and TikTok-ready security practices.**

## 🚀 Features

This template comes packed with modern authentication and authorization features to kickstart your next project:

- **🔐 Secure Authentication**: Complete Login and Registration flows using HTTP-only cookies and bcrypt password hashing.
- **🛡️ RBAC (Role-Based Access Control)**: Granular permissions system to manage User and Admin roles effectively.
- **🎫 JWT Session Management**: Secure Access and Refresh Token rotation strategy for persistent and safe user sessions.
- **🔑 OAuth Integration**: (Coming Soon) Seamless login with Google, GitHub, and other providers.
- **📱 2FA (Two-Factor Authentication)**: (Coming Soon) Add an extra layer of security with TOTP-based two-factor authentication.
- **📧 Email Verification**: Verify user identities upon registration to prevent spam.
- **🔄 Password Management**: Secure "Forgot Password" and "Reset Password" flows with email notifications.
- **🛡️ Security First**: Implements best practices like Rate Limiting, Helmet, and Data Sanitization.

## 🛠️ Tech Stack

Built with a focus on performance, type safety, and scalability:

- **Runtime**: [Node.js](https://nodejs.org/)
- **Framework**: [Express.js](https://expressjs.com/)
- **Language**: [TypeScript](https://www.typescriptlang.org/)
- **Database**: [MongoDB](https://www.mongodb.com/) (Mongoose ODM)
- **Validation**: [Zod](https://zod.dev/)
- **Authentication**: [JsonWebToken](https://github.com/auth0/node-jsonwebtoken) & [Bcrypt.js](https://github.com/dcodeIO/bcrypt.js)
- **Email**: [Nodemailer](https://nodemailer.com/)

## 🏁 Getting Started

Follow these steps to set up the project locally on your machine.

### Prerequisites

Ensure you have the following installed:

- **Node.js** (v18+ recommended)
- **MongoDB** (Local instance or Atlas URI)

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/advance-auth.git
   cd advance-auth
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Configure Environment Variables**
   Create a `.env` file in the root directory and populate it with your secrets:

   ```env
   NODE_ENV=development
   PORT=5000

   # Database
   MONGO_URI=mongodb://localhost:27017/advance_auth

   # JWT Secrets (Generate strong random strings)
   JWT_ACCESS_SECRET=your_super_secret_access_key
   JWT_REFRESH_SECRET=your_super_secret_refresh_key

   # Email Service (SMTP)
   SMTP_HOST=smtp.example.com
   SMTP_PORT=587
   SMTP_USER=your_email@example.com
   SMTP_PASS=your_email_password
   EMAIL_FROM=no-reply@example.com

   # Application URL
   APP_URL=http://localhost:5000
   ```

4. **Run the Application**

   **Development Mode:**

   ```bash
   npm run dev
   ```

   **Production Build:**

   ```bash
   npm run build
   npm start
   ```

## 📡 API Endpoints

Brief overview of the main authentication routes:

| Method | Endpoint                | Description                              |
| :----- | :---------------------- | :--------------------------------------- |
| `POST` | `/auth/register`        | Register a new user                      |
| `POST` | `/auth/login`           | Login and receive tokens                 |
| `POST` | `/auth/refresh`         | Refresh access token using refresh token |
| `POST` | `/auth/logout`          | Logout user (clears cookies)             |
| `GET`  | `/auth/verify-email`    | Verify user email address                |
| `POST` | `/auth/forgot-password` | Request password reset link              |
| `POST` | `/auth/reset-password`  | Set a new password                       |

## 🗺️ Roadmap

- [x] Basic Auth (Register/Login/Logout)
- [x] Email Verification & Password Reset
- [ ] OAuth Strategies (Google/GitHub)
- [ ] Two-Factor Authentication (2FA)
- [ ] Admin Dashboard for User Management

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements.

---

**Happy Coding!** 🚀
