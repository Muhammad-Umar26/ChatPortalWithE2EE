# Chat Portal (FastAPI + React + E2EE)

This project is now an authenticated, multi-room chat portal with persistent room/message records, frontend end-to-end encryption, and distributed FTPS-backed file storage.

## Features Implemented

- User registration and login (persistent user records in SQLite)
- Home/landing page and auth pages
- Room dashboard:
  - Create room (creator becomes owner)
  - Join room by room ID
  - Transfer ownership and leave (owner flow)
  - Owner can remove members
  - Delete room (owner only)
- Room-based WebSocket chat (`/ws/{room_id}`)
- Persistent message history in database (stored as encrypted packet payloads)
- Sender-side message deletion (renders "This message was deleted")
- E2EE retained:
  - Backend never decrypts ciphertext
  - Frontend encrypts before send and decrypts after receive
- Distributed encrypted file sharing:
  - 3 local FTPS servers on ports `2121`, `2122`, `2123`
  - File chunks are split across separate FTP server directories
  - File metadata and chunk location are tracked in SQLite
  - File messages render as clickable downloads in the chat UI
- Room history is filtered by join time so new members only see messages sent after they joined

## Project Structure

```text
Project/
  backend/
    main.py
    requirements.txt
    chat_portal.db              # Auto-created on first backend run
    ftp_servers.py               # Launches the 3 local FTPS storage servers
    ftp_data/                    # Local chunk storage, one directory per FTP server
  frontend/
    index.html
    package.json
    vite.config.js
    src/
      App.jsx
      crypto.js
      main.jsx
      styles.css
  .gitignore
  README.md
```

## Backend Setup

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python ftp_servers.py

uvicorn main:app --host 0.0.0.0 --port 8000 --reload --ssl-keyfile .\certs\localhost-key.pem --ssl-certfile .\certs\localhost.pem
```

Health: `GET http://localhost:8000/health`

### FTPS storage servers

The file storage layer is now a separate FTPS process started with `python ftp_servers.py` from the `backend` folder.

- Server 1: `0.0.0.0:2121`
- Server 2: `0.0.0.0:2122`
- Server 3: `0.0.0.0:2123`

Each server writes to its own local directory under `backend/ftp_data/` and uses passive mode with TLS.

### Backend network/CORS configuration (important for LAN access)

When frontend is opened from a LAN IP (for example `http://192.168.x.x:5173`), configure CORS if needed:

```bash
# Optional explicit list (comma-separated)
set CORS_ALLOW_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://192.168.100.20:5173

# Optional custom regex override
set CORS_ALLOW_ORIGIN_REGEX=^https?://(localhost|127\.0\.0\.1|192\.168(?:\.\d{1,3}){2})(:\d+)?$
```

## Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Open: `http://localhost:5173`

### Frontend API/WS configuration

The app now auto-detects host from browser URL and targets:
- API: `http(s)://<current-host>:8000`
- WS: `ws(s)://<current-host>:8000/ws`

If you run the backend with the local TLS certs, the browser should be opened over `https://` so the frontend uses secure `https`/`wss` connections.

You can override with Vite env variables:

```bash
# frontend/.env
VITE_API_BASE_URL=http://192.168.100.20:8000
VITE_WS_BASE_URL=ws://192.168.100.20:8000/ws
```

Note: frontend now includes a `node-forge` fallback for browser environments where `window.crypto.subtle` is unavailable (commonly non-HTTPS LAN contexts). Run `npm install` after pulling latest changes.

## File Sharing Flow

1. The sender selects a file in the React frontend.
2. The frontend creates a fresh AES-GCM key for that file and encrypts the file bytes in the browser.
3. The AES key is wrapped per recipient using each recipient's RSA public key.
4. The encrypted file is uploaded to `POST /ftp/upload`.
5. The backend splits the encrypted file into chunks and stores them across the 3 FTPS servers.
6. The backend records chunk metadata in SQLite.
7. Recipients click the file message in chat, download the encrypted file from `GET /ftp/download/{file_id}`, then decrypt it locally in the browser.

This means the file itself is encrypted before it leaves the sender's browser, stays encrypted while stored on the FTPS servers, and is only decrypted on the receiving browser.

## Core API Endpoints

### Auth
- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`
- `POST /auth/ping` (heartbeat to keep online presence fresh)
- `POST /auth/logout`
- `PUT /auth/public-key`

### Rooms
- `GET /rooms`
- `POST /rooms`
- `POST /rooms/{room_id}/join`
- `POST /rooms/{room_id}/leave` (non-owner members only)
- `POST /rooms/{room_id}/owner-leave` (owner transfers ownership, then leaves)
- `POST /rooms/{room_id}/remove-member` (owner removes a member)
- `DELETE /rooms/{room_id}` (owner only)
- `GET /rooms/{room_id}/members`
- `GET /rooms/{room_id}/messages?limit=200`
- `POST /rooms/{room_id}/messages/{message_id}/delete` (sender deletes their own message)

### FTP Placeholder
- `POST /ftp/upload` (accepts an already encrypted file, stores chunks on distributed FTPS servers)
- `GET /ftp/download/{file_id}` (reassembles encrypted chunks from FTPS and streams the encrypted file back to the client)

### WebSocket
- `GET ws://localhost:8000/ws/{room_id}?token=<access_token>`

## E2EE Flow (Current Implementation)

1. Client logs in and loads/generates persistent RSA keypair in browser storage.
2. Client uploads public key to backend (`PUT /auth/public-key`).
3. In room chat, sender creates one ephemeral AES key per message.
4. Message plaintext is encrypted via AES-GCM.
5. AES key is encrypted per recipient with recipient RSA public key.
6. Server stores and relays only encrypted packet JSON (no plaintext decryption).
7. Recipient decrypts wrapped AES key with private RSA key, then decrypts ciphertext locally.

Message history is scoped to each member's join time, so newly added members do not receive old unreadable encrypted backlog from before they joined.

File encryption uses the same browser-side pattern at a higher level:

- Text messages are encrypted in the frontend with AES-GCM, and the AES key is wrapped with RSA per recipient.
- Files are also encrypted in the frontend with AES-GCM before upload.
- The backend only stores and serves encrypted file chunks; it does not decrypt the file contents.
- Recipients decrypt the wrapped AES key in the browser, download the encrypted file, and decrypt it locally with the same AES key.

So yes, the files are encrypted too, and the encryption model is intentionally similar to text messages: browser-side AES-GCM plus RSA-wrapped AES keys per recipient.

Online status is presence-based (heartbeat + timeout), not room-tab-based. This means room online counts reflect members currently online in the app, even if they are on dashboard and not currently inside that specific room view.

## Important Security Note

E2EE is implemented at application level.  
For transport security in deployment, switch to HTTPS/WSS (TLS) with proper certificates.

## Database Note (SQLite in Production)

SQLite works well for single-server deployments and small-to-medium traffic. It is not ideal for multi-instance/cloud autoscaling setups because it is file-based and not designed for many concurrent writers across distributed nodes.  
For production at larger scale, migrate to PostgreSQL (or similar server database) while keeping the same API/application flow.
