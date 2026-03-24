# Firebase Security Tester

A browser-based tool for probing the security rules of a Firebase project. Paste your Firebase web config, configure per-service options, and run read/write tests against Authentication, Realtime Database, Firestore, and Storage, all from a single page.

> **Disclaimer:** This tool is intended for use on projects you own or have explicit permission to test. Never run it against third-party projects without authorisation.

---

## Features

- **Credentials input** - paste any Firebase web config JSON, or use JavaScript-style object syntax (unquoted keys supported via JSON5). The Firebase app instance is automatically refreshed whenever credentials change.
- **Authentication probes**
  - Email/Password login or signup (configurable email + password)
  - Anonymous sign-in
  - Check current session
  - Sign out
  - **Bulk signup** - creates N users from a base email pattern (e.g. `someone@gmail.com` -> `someone1@gmail.com` ... `someoneN@gmail.com`); stops immediately on first error and reports exactly where it failed.
- **Realtime Database probes** - configurable path (defaults to root `/`) and custom write payload (JSON/JS-object syntax).
- **Firestore probes** - configurable document path and custom write payload (merged with `probedAt` server timestamp).
- **Storage probes** - configurable folder/object path, list objects, and file upload (select any local file).
- **Per-category results** - each service section shows its own result history with a local Clear button. Results are colour-coded: green for allowed, red for denied/error.
- **Persistent config** - all inputs (credentials, paths, payloads, auth settings) are automatically saved to `localStorage` and restored on page reload.

---

## Getting Started

### Prerequisites

- Node.js ≥ 20
- npm

### Installation

```bash
npm install
```

### Development

```bash
npm run dev
```

The app will be available at `http://localhost:5173`.

### Type-check

```bash
npm run typecheck
```

### Production build

```bash
npm run build
npm start
```

---

## Usage

1. Open the app in your browser.
2. **Credentials** - paste your Firebase web app config JSON (or JS-style object) into the textarea at the top. The app instance will be created/refreshed automatically.
3. **Authentication** - select a mode (login or signup), enter credentials, and click **Run Login / Run Signup**. Use **Bulk Signup** to stress-test user creation limits.
4. **Realtime Database** - set the probe path (leave as `/` to target the root) and optionally edit the write payload, then click **Read** or **Write**.
5. **Firestore** - set the document path (must be an even number of segments, e.g. `collection/document`), edit the write payload, then click **Read Document** or **Write Document**.
6. **Storage** - set the bucket path, optionally select a file, then click **List** or **Upload**.

> Results appear directly inside each section. Allowed operations show in green; permission-denied or other errors show in red with the full error message.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | React 19 + React Router 7 |
| Language | TypeScript 5 |
| Styling | Tailwind CSS v4 |
| Build tool | Vite |
| Firebase SDK | Firebase JS SDK v12 |
| Config parsing | JSON5 |

---

## Docker

```bash
docker build -t firebase-security-tester .
docker run -p 3000:3000 firebase-security-tester
```

---

## Project Structure

```
app/
├── routes/
│   └── home.tsx          # Root route, renders Welcome
├── welcome/
│   └── welcome.tsx       # Full tester UI and probe logic
├── root.tsx              # App shell + error boundary
└── app.css               # Tailwind entry
```

---

## Notes

- **File input** cannot be persisted across page reloads due to browser security restrictions. Re-select the file after each reload.
- This tool uses the **client-side Firebase SDK** and operates under the same security rules as any end-user browser client. It cannot bypass server-side Admin SDK restrictions.
- Credentials are stored only in your browser's `localStorage` and are never sent to any server by this tool.

