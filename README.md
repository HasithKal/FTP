## Features

- **No External Dependencies:** Built entirely with core Java standard libraries (`java.io`, `java.net`, `java.nio`).
- **Concurrent Connections:** Uses `Executors.newCachedThreadPool()` to handle multiple client sessions simultaneously.
- **Data Transfer Modes:**
  - **Passive Mode (`PASV`):** Ephemeral server port allocation with automatic binding.
  - **Active Mode (`PORT`):** Client-specified reverse data connections with strict origin IP verification (anti-bounce protection).
- **Directory Sandboxing (Chroot):** Strict virtual-path resolution prevents directory traversal attacks outside the designated root folder (`../../`).
- **Security & Resilience:**
  - Maximum failed login threshold (`3 attempts`) before auto-disconnect.
  - Constant-time password verification via `MessageDigest.isEqual` to mitigate timing attacks.
  - Command masking for `PASS` in server-side logs.
  - Socket read timeout (`300s` idle control channel, `10s` data handshake).
- **Built-in Demo Runner:** Integrated test client to demonstrate end-to-end functionality without external software.
