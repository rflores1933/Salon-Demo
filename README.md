# Salon

A distraction-free study platform. Log in, set an intention for what you're working on, and use the whiteboard for scratch thinking while you focus. The whiteboard is session-scoped — when you log out, it dissolves.

## Run it locally

```bash
git clone https://github.com/YOUR-USERNAME/salon-demo.git
cd salon-demo
npm install

cp .env.example .env
# Generate a session secret and paste it into .env:
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

node app.js
```

Visit `http://localhost:3000`. Requires Node.js 20 or later.

## Stack

Node.js · Express · EJS · SQLite (better-sqlite3) · bcrypt · Helmet · express-session

---

Rommel Flores