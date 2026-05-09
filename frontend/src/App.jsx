import { useEffect, useMemo, useRef, useState } from "react";
import {
  aesDecrypt,
  aesEncrypt,
  decryptWithPrivateKey,
  encryptWithPublicKey,
  exportAesRawToBase64,
  exportKeyPairToJwk,
  exportPublicKeyToBase64,
  generateAesKey,
  generateRsaKeyPair,
  importAesRawFromBase64,
  importKeyPairFromJwk,
  importPublicKeyFromBase64
} from "./crypto";

const runtimeHttpProtocol = window.location.protocol === "https:" ? "https" : "http";
const runtimeWsProtocol = window.location.protocol === "https:" ? "wss" : "ws";
const runtimeHost = window.location.hostname;
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || `${runtimeHttpProtocol}://${runtimeHost}:8000`;
const WS_BASE_URL =
  import.meta.env.VITE_WS_BASE_URL || `${runtimeWsProtocol}://${runtimeHost}:8000/ws`;
const TOKEN_STORAGE_KEY = "chat_portal_token";
const USER_STORAGE_KEY = "chat_portal_user";
const KEY_STORAGE_PREFIX = "chat_portal_e2ee_keys_v1";
const QUICK_EMOJIS = ["😀", "😄", "😂", "😍", "🤔", "😎", "🔥", "👍", "👏", "🎉", "❤️", "🙏"];

function parseStoredUser() {
  const raw = localStorage.getItem(USER_STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function buildErrorMessage(error) {
  if (!error) return "Unknown error";
  return error.message || "Unknown error";
}

function App() {
  const [booting, setBooting] = useState(true);
  const [view, setView] = useState("landing");
  const [authMode, setAuthMode] = useState("login");
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_STORAGE_KEY) || "");
  const [user, setUser] = useState(() => parseStoredUser());
  const [banner, setBanner] = useState("");

  const [authForm, setAuthForm] = useState({
    username: "",
    password: "",
    displayName: ""
  });
  const [authLoading, setAuthLoading] = useState(false);

  const [rooms, setRooms] = useState([]);
  const [roomLoading, setRoomLoading] = useState(false);
  const [createRoomName, setCreateRoomName] = useState("");
  const [joinRoomId, setJoinRoomId] = useState("");

  const [activeRoom, setActiveRoom] = useState(null);
  const [socketStatus, setSocketStatus] = useState("Disconnected");
  const [roomMembers, setRoomMembers] = useState([]);
  const [messages, setMessages] = useState([]);
  const [messageInput, setMessageInput] = useState("");
  const [emojiOpen, setEmojiOpen] = useState(false);

  const wsRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const shouldReconnectRef = useRef(false);
  const activeRoomRef = useRef(null);
  const keyPairRef = useRef(null);
  const publicKeyBase64Ref = useRef("");
  const memberPublicKeysRef = useRef(new Map());
  const messageEndRef = useRef(null);
  const fileInputRef = useRef(null);

  const roomTitle = useMemo(() => {
    if (!activeRoom) return "";
    return `${activeRoom.name} (${activeRoom.id})`;
  }, [activeRoom]);

  useEffect(() => {
    activeRoomRef.current = activeRoom;
  }, [activeRoom]);

  useEffect(() => {
    if (messageEndRef.current) {
      messageEndRef.current.scrollIntoView({ behavior: "smooth", block: "end" });
    }
  }, [messages]);

  useEffect(() => {
    document.body.classList.toggle("room-active", view === "room");
    return () => {
      document.body.classList.remove("room-active");
    };
  }, [view]);

  useEffect(() => {
    return () => {
      closeSocketConnection(false);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function bootstrapSession() {
      if (!token || !user) {
        setBooting(false);
        setView("landing");
        return;
      }

      try {
        const me = await apiRequest("/auth/me", { authToken: token });
        if (cancelled) return;
        setUser(me.user);
        await ensureUserKeys(token, me.user);
        await loadRooms(token);
        setView("dashboard");
      } catch {
        if (cancelled) return;
        clearSession();
        setView("landing");
      } finally {
        if (!cancelled) {
          setBooting(false);
        }
      }
    }

    void bootstrapSession();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function apiRequest(path, { method = "GET", body, authToken = token } = {}) {
    const headers = {};
    if (body) headers["Content-Type"] = "application/json";
    if (authToken) headers.Authorization = `Bearer ${authToken}`;

    let response;
    try {
      response = await fetch(`${API_BASE_URL}${path}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined
      });
    } catch {
      throw new Error(
        `Cannot reach backend at ${API_BASE_URL}. Start FastAPI and ensure CORS allows this frontend origin.`
      );
    }

    const isJson = (response.headers.get("content-type") || "").includes("application/json");
    const data = isJson ? await response.json() : null;

    if (!response.ok) {
      const detail = data?.detail || `Request failed (${response.status})`;
      const error = new Error(detail);
      error.status = response.status;
      throw error;
    }

    return data;
  }

  async function ensureUserKeys(authToken, authUser) {
    try {
      const storageKey = `${KEY_STORAGE_PREFIX}:${authUser.id}`;
      let keyPair = null;
      const rawKeys = localStorage.getItem(storageKey);

      if (rawKeys) {
        try {
          const parsed = JSON.parse(rawKeys);
          keyPair = await importKeyPairFromJwk(parsed.publicJwk, parsed.privateJwk);
        } catch {
          localStorage.removeItem(storageKey);
        }
      }

      if (!keyPair) {
        keyPair = await generateRsaKeyPair();
        const jwkBundle = await exportKeyPairToJwk(keyPair);
        localStorage.setItem(storageKey, JSON.stringify(jwkBundle));
      }

      keyPairRef.current = keyPair;
      publicKeyBase64Ref.current = await exportPublicKeyToBase64(keyPair.publicKey);
      await apiRequest("/auth/public-key", {
        method: "PUT",
        authToken,
        body: { public_key: publicKeyBase64Ref.current }
      });
    } catch {
      throw new Error(
        "Unable to initialize E2EE keys on this browser. Refresh and retry, then run npm install in frontend if dependencies were updated."
      );
    }
  }

  function storeSession(sessionToken, sessionUser) {
    localStorage.setItem(TOKEN_STORAGE_KEY, sessionToken);
    localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(sessionUser));
    setToken(sessionToken);
    setUser(sessionUser);
  }

  function clearSession() {
    closeSocketConnection(false);
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    localStorage.removeItem(USER_STORAGE_KEY);
    setToken("");
    setUser(null);
    setRooms([]);
    setActiveRoom(null);
    setRoomMembers([]);
    setMessages([]);
    setMessageInput("");
    setSocketStatus("Disconnected");
    setBanner("");
    memberPublicKeysRef.current = new Map();
    keyPairRef.current = null;
    publicKeyBase64Ref.current = "";
  }

  async function loadRooms(authToken = token) {
    const data = await apiRequest("/rooms", { authToken });
    setRooms(data.rooms || []);
  }

  function closeSocketConnection(allowReconnect) {
    shouldReconnectRef.current = allowReconnect;
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    const socket = wsRef.current;
    wsRef.current = null;
    if (socket && socket.readyState <= 1) {
      socket.close(1000, "Closing socket");
    }
  }

  function appendSystemMessage(content) {
    setMessages((prev) => [
      ...prev,
      {
        id: `${Date.now()}-${Math.random()}`,
        sender: "System",
        senderId: 0,
        content,
        timestamp: new Date().toISOString(),
        type: "system",
        own: false
      }
    ]);
  }

  function formatOnlineStatus(packet) {
    const fallback = Math.max((Number(packet?.onlineCount) || 0) - 1, 0);
    const parsedPeerCount = Number(packet?.peerOnlineCount);
    const peersOnline = Number.isFinite(parsedPeerCount) ? Math.max(parsedPeerCount, 0) : fallback;
    return `Connected (${peersOnline} online)`;
  }

  async function hydratePacketToMessage(packet, fallbackMeta = {}) {
    if (!packet || typeof packet !== "object") {
      return null;
    }

    if (packet.type === "chat") {
      const senderId = Number(packet.senderId ?? fallbackMeta?.sender?.id ?? 0);
      const senderName =
        packet.sender ||
        fallbackMeta?.sender?.display_name ||
        fallbackMeta?.sender?.username ||
        "Unknown";
      const senderUsername = packet.senderUsername || fallbackMeta?.sender?.username || "";

      const wrappedAesKey =
        packet?.encryptedKeys?.[String(user?.id)] ?? packet?.encryptedKeys?.[user?.id];

      if (!wrappedAesKey || !keyPairRef.current?.privateKey) {
        return null;
      }

      let content = "";
      let decryptFailed = false;
      try {
        const aesRawBase64 = await decryptWithPrivateKey(keyPairRef.current.privateKey, wrappedAesKey);
        const aesKey = await importAesRawFromBase64(aesRawBase64);
        content = await aesDecrypt(aesKey, packet.iv, packet.ciphertext);
      } catch {
        decryptFailed = true;
        content = "[Unable to decrypt this message]";
      }

      return {
        id: `${fallbackMeta.id || Date.now()}-${Math.random()}`,
        senderId,
        sender:
          senderId === user?.id
            ? "You"
            : senderUsername
              ? `${senderName} (@${senderUsername})`
              : senderName,
        content,
        timestamp: packet.sentAt || fallbackMeta.created_at || new Date().toISOString(),
        type: decryptFailed ? "error" : "chat",
        own: senderId === user?.id
      };
    }

    if (packet.type === "member_joined") {
      return {
        id: `${Date.now()}-${Math.random()}`,
        sender: "System",
        senderId: 0,
        content: `${packet.sender} joined the room`,
        timestamp: packet.sentAt || new Date().toISOString(),
        type: "system",
        own: false
      };
    }

    if (packet.type === "member_left") {
      return {
        id: `${Date.now()}-${Math.random()}`,
        sender: "System",
        senderId: 0,
        content: `${packet.sender} left the room`,
        timestamp: packet.sentAt || new Date().toISOString(),
        type: "system",
        own: false
      };
    }

    if (packet.type === "file-intent") {
      return {
        id: `${Date.now()}-${Math.random()}`,
        sender: "System",
        senderId: 0,
        content: `${packet.sender} wants to send file: ${packet.fileName} (${packet.fileSize} bytes). FTP module pending integration.`,
        timestamp: packet.sentAt || new Date().toISOString(),
        type: "system",
        own: false
      };
    }

    return null;
  }

  async function handleRealtimePacket(roomId, packet) {
    if (!packet || typeof packet !== "object") return;
    if (packet.roomId && packet.roomId !== roomId) return;

    if (packet.type === "server_ack") {
      setSocketStatus(formatOnlineStatus(packet));
      return;
    }

    if (packet.type === "online_count") {
      setSocketStatus(formatOnlineStatus(packet));
      return;
    }

    if (packet.type === "announce" && packet.senderId && packet.publicKey) {
      memberPublicKeysRef.current.set(String(packet.senderId), packet.publicKey);
      setRoomMembers((prev) => {
        const existing = prev.find((member) => member.id === packet.senderId);
        if (!existing) {
          return [
            ...prev,
            {
              id: packet.senderId,
              username: packet.senderUsername || "",
              display_name: packet.sender || "Unknown",
              public_key: packet.publicKey
            }
          ];
        }
        return prev.map((member) =>
          member.id === packet.senderId ? { ...member, public_key: packet.publicKey } : member
        );
      });
      return;
    }

    if (packet.type === "member_joined") {
      setRoomMembers((prev) => {
        if (prev.some((member) => member.id === packet.senderId)) {
          return prev;
        }
        return [
          ...prev,
          {
            id: packet.senderId,
            username: packet.senderUsername || "",
            display_name: packet.sender || "Unknown",
            public_key: null
          }
        ];
      });
      if (packet.senderId !== user?.id) {
        appendSystemMessage(`${packet.sender} joined the room`);
      }
      return;
    }

    if (packet.type === "member_left") {
      memberPublicKeysRef.current.delete(String(packet.senderId));
      setRoomMembers((prev) => prev.filter((member) => member.id !== packet.senderId));
      if (packet.senderId !== user?.id) {
        appendSystemMessage(`${packet.sender} left the room`);
      }
      return;
    }

    if (packet.type === "room_deleted") {
      appendSystemMessage(`Room was deleted by ${packet.deletedBy}`);
      closeSocketConnection(false);
      setActiveRoom(null);
      setView("dashboard");
      await loadRooms();
      return;
    }

    const nextMessage = await hydratePacketToMessage(packet);
    if (nextMessage) {
      setMessages((prev) => [...prev, nextMessage]);
    }
  }

  function connectRoomSocket(roomId) {
    if (!token || !roomId) return;

    closeSocketConnection(false);
    shouldReconnectRef.current = true;
    setSocketStatus("Connecting...");

    const socket = new WebSocket(`${WS_BASE_URL}/${encodeURIComponent(roomId)}?token=${encodeURIComponent(token)}`);
    wsRef.current = socket;

    socket.onopen = () => {
      setSocketStatus("Connected (0 online)");
      const announcePacket = {
        type: "announce",
        roomId,
        publicKey: publicKeyBase64Ref.current,
        sentAt: new Date().toISOString()
      };
      socket.send(JSON.stringify(announcePacket));
    };

    socket.onmessage = (event) => {
      const packet = safeJsonParse(event.data);
      if (!packet) return;
      void handleRealtimePacket(roomId, packet);
    };

    socket.onerror = () => {
      setSocketStatus("Socket error");
    };

    socket.onclose = () => {
      wsRef.current = null;
      setSocketStatus("Disconnected");
      const currentRoom = activeRoomRef.current;

      if (shouldReconnectRef.current && currentRoom?.id === roomId) {
        reconnectTimerRef.current = setTimeout(() => {
          connectRoomSocket(roomId);
        }, 1500);
      }
    };
  }

  async function openRoom(room) {
    setBanner("");
    setActiveRoom(room);
    setMessages([]);
    setRoomMembers([]);
    setEmojiOpen(false);
    memberPublicKeysRef.current = new Map();
    setView("room");
    setSocketStatus("Loading...");

    try {
      const [memberData, messageData] = await Promise.all([
        apiRequest(`/rooms/${room.id}/members`),
        apiRequest(`/rooms/${room.id}/messages?limit=200`)
      ]);

      const members = memberData.members || [];
      setRoomMembers(members);

      const memberKeyMap = new Map();
      for (const member of members) {
        if (member.public_key) {
          memberKeyMap.set(String(member.id), member.public_key);
        }
      }
      if (user?.id && publicKeyBase64Ref.current) {
        memberKeyMap.set(String(user.id), publicKeyBase64Ref.current);
      }
      memberPublicKeysRef.current = memberKeyMap;

      const hydrated = [];
      for (const rawMessage of messageData.messages || []) {
        const built = await hydratePacketToMessage(rawMessage.packet, rawMessage);
        if (built) {
          hydrated.push(built);
        }
      }
      setMessages(hydrated);
      connectRoomSocket(room.id);
    } catch (error) {
      setBanner(`Failed to open room: ${buildErrorMessage(error)}`);
      setView("dashboard");
      setActiveRoom(null);
      setSocketStatus("Disconnected");
    }
  }

  function leaveRoom() {
    closeSocketConnection(false);
    setActiveRoom(null);
    setRoomMembers([]);
    setMessages([]);
    setMessageInput("");
    setEmojiOpen(false);
    setView("dashboard");
    setSocketStatus("Disconnected");
    setBanner("");
  }

  async function submitAuth(event) {
    event.preventDefault();
    setBanner("");
    setAuthLoading(true);

    try {
      const endpoint = authMode === "register" ? "/auth/register" : "/auth/login";
      const payload = {
        username: authForm.username.trim(),
        password: authForm.password
      };
      if (authMode === "register" && authForm.displayName.trim()) {
        payload.display_name = authForm.displayName.trim();
      }

      const data = await apiRequest(endpoint, { method: "POST", body: payload, authToken: "" });
      storeSession(data.token, data.user);
      await ensureUserKeys(data.token, data.user);
      await loadRooms(data.token);
      setAuthForm({ username: "", password: "", displayName: "" });
      setView("dashboard");
    } catch (error) {
      setBanner(buildErrorMessage(error));
    } finally {
      setAuthLoading(false);
    }
  }

  async function createRoom(event) {
    event.preventDefault();
    if (!createRoomName.trim()) return;
    setBanner("");

    try {
      setRoomLoading(true);
      const response = await apiRequest("/rooms", {
        method: "POST",
        body: { name: createRoomName.trim() }
      });
      setCreateRoomName("");
      await loadRooms();
      await openRoom(response.room);
    } catch (error) {
      setBanner(buildErrorMessage(error));
    } finally {
      setRoomLoading(false);
    }
  }

  async function joinRoom(event) {
    event.preventDefault();
    if (!joinRoomId.trim()) return;
    setBanner("");

    try {
      setRoomLoading(true);
      const response = await apiRequest(`/rooms/${joinRoomId.trim()}/join`, { method: "POST" });
      setJoinRoomId("");
      await loadRooms();
      await openRoom(response.room);
    } catch (error) {
      setBanner(buildErrorMessage(error));
    } finally {
      setRoomLoading(false);
    }
  }

  async function deleteRoom(roomId) {
    setBanner("");
    try {
      await apiRequest(`/rooms/${roomId}`, { method: "DELETE" });
      if (activeRoomRef.current?.id === roomId) {
        leaveRoom();
      }
      await loadRooms();
    } catch (error) {
      setBanner(buildErrorMessage(error));
    }
  }

  async function leaveRoomMembership(roomId) {
    setBanner("");
    try {
      if (activeRoomRef.current?.id === roomId) {
        closeSocketConnection(false);
      }
      await apiRequest(`/rooms/${roomId}/leave`, { method: "POST" });
      if (activeRoomRef.current?.id === roomId) {
        leaveRoom();
      }
      await loadRooms();
    } catch (error) {
      setBanner(buildErrorMessage(error));
    }
  }

  async function sendMessage() {
    const plaintext = messageInput.trim();
    if (!plaintext || !activeRoom || !user) return;

    const socket = wsRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      setBanner("WebSocket is disconnected. Wait for reconnect and try again.");
      return;
    }

    try {
      const recipientKeyMap = new Map(memberPublicKeysRef.current);
      if (publicKeyBase64Ref.current) {
        recipientKeyMap.set(String(user.id), publicKeyBase64Ref.current);
      }

      if (recipientKeyMap.size === 0) {
        setBanner("No public keys found in this room yet.");
        return;
      }

      const missingKeys = roomMembers.filter((member) => !recipientKeyMap.get(String(member.id)));
      if (missingKeys.length > 0) {
        appendSystemMessage(
          `Warning: ${missingKeys.length} room member(s) have no public key yet and may not decrypt this message.`
        );
      }

      const aesKey = await generateAesKey();
      const aesRawBase64 = await exportAesRawToBase64(aesKey);
      const encryptedKeys = {};

      for (const [recipientId, recipientPublicKeyBase64] of recipientKeyMap.entries()) {
        const recipientPublicKey = await importPublicKeyFromBase64(recipientPublicKeyBase64);
        encryptedKeys[recipientId] = await encryptWithPublicKey(recipientPublicKey, aesRawBase64);
      }

      const { iv, ciphertext } = await aesEncrypt(aesKey, plaintext);
      socket.send(
        JSON.stringify({
          type: "chat",
          roomId: activeRoom.id,
          encryptedKeys,
          iv,
          ciphertext,
          sentAt: new Date().toISOString()
        })
      );

      setMessageInput("");
      setEmojiOpen(false);
    } catch (error) {
      appendSystemMessage(`Message send failed: ${buildErrorMessage(error)}`);
    }
  }

  function appendEmoji(emoji) {
    setMessageInput((prev) => `${prev}${emoji}`);
  }

  async function handleFilePicked(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || !activeRoom) return;

    try {
      await apiRequest("/ftp/upload-placeholder", {
        method: "POST",
        body: {
          room_id: activeRoom.id,
          file_name: file.name,
          file_size: file.size,
          content_type: file.type || "application/octet-stream"
        }
      });
    } catch (error) {
      appendSystemMessage(`FTP module placeholder: ${buildErrorMessage(error)}`);
    }

    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(
        JSON.stringify({
          type: "file-intent",
          roomId: activeRoom.id,
          fileName: file.name,
          fileSize: file.size,
          contentType: file.type || "application/octet-stream",
          sentAt: new Date().toISOString()
        })
      );
    }
  }

  function signOut() {
    clearSession();
    setView("landing");
  }

  if (booting) {
    return (
      <div className="screen centered">
        <div className="card">
          <h1>Chat Portal</h1>
          <p>Loading your secure workspace...</p>
        </div>
      </div>
    );
  }

  if (view === "landing") {
    return (
      <div className="screen centered">
        <div className="card landing-card">
          <h1>Chat Portal</h1>
          <p>
            Authenticated multi-room chat with end-to-end encryption.
          </p>
          <div className="row">
            <button
              onClick={() => {
                setAuthMode("login");
                setView("auth");
                setBanner("");
              }}
            >
              Login
            </button>
            <button
              className="secondary"
              onClick={() => {
                setAuthMode("register");
                setView("auth");
                setBanner("");
              }}
            >
              Register
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (view === "auth") {
    return (
      <div className="screen centered">
        <div className="card auth-card">
          <h2>{authMode === "register" ? "Create account" : "Welcome back"}</h2>
          <form onSubmit={submitAuth} className="form-stack">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              value={authForm.username}
              onChange={(event) =>
                setAuthForm((prev) => ({
                  ...prev,
                  username: event.target.value
                }))
              }
              placeholder="e.g. alice"
              required
            />

            {authMode === "register" && (
              <>
                <label htmlFor="displayName">Display Name</label>
                <input
                  id="displayName"
                  value={authForm.displayName}
                  onChange={(event) =>
                    setAuthForm((prev) => ({
                      ...prev,
                      displayName: event.target.value
                    }))
                  }
                  placeholder="e.g. Alice Khan"
                />
              </>
            )}

            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={authForm.password}
              onChange={(event) =>
                setAuthForm((prev) => ({
                  ...prev,
                  password: event.target.value
                }))
              }
              placeholder="Minimum 8 characters"
              required
            />

            <button type="submit" disabled={authLoading}>
              {authLoading ? "Please wait..." : authMode === "register" ? "Register" : "Login"}
            </button>
          </form>
          <div className="row small-gap auth-links">
            <button
              className="link-button"
              onClick={() => setAuthMode((prev) => (prev === "login" ? "register" : "login"))}
            >
              {authMode === "login" ? "Need an account? Register" : "Already have an account? Login"}
            </button>
            <button className="link-button" onClick={() => setView("landing")}>
              Back to home
            </button>
          </div>
          {banner && <p className="error-text">{banner}</p>}
        </div>
      </div>
    );
  }

  if (view === "dashboard") {
    return (
      <div className="dashboard-shell">
        <aside className="dashboard-sidebar">
          <h1>Chat Portal</h1>
          <p>
            Logged in as <strong>{user?.display_name}</strong>
          </p>
          <p className="muted">@{user?.username}</p>
          <button className="danger" onClick={signOut}>
            Logout
          </button>
        </aside>

        <main className="dashboard-main">
          <header className="dashboard-header">
            <h2>Your Chat Rooms</h2>
            <span>{rooms.length} room(s)</span>
          </header>

          <section className="dashboard-controls">
            <form onSubmit={createRoom} className="inline-form">
              <input
                value={createRoomName}
                onChange={(event) => setCreateRoomName(event.target.value)}
                placeholder="Create room name"
              />
              <button type="submit" disabled={roomLoading}>
                Create Room
              </button>
            </form>
            <form onSubmit={joinRoom} className="inline-form">
              <input
                value={joinRoomId}
                onChange={(event) => setJoinRoomId(event.target.value)}
                placeholder="Join by Room ID"
              />
              <button type="submit" disabled={roomLoading}>
                Join Room
              </button>
            </form>
          </section>

          <section className="room-grid">
            {rooms.length === 0 ? (
              <div className="card">
                <p>No rooms yet. Create one or join with a Room ID.</p>
              </div>
            ) : (
              rooms.map((room) => (
                <article key={room.id} className="room-card">
                  <h3>{room.name}</h3>
                  <p>
                    <strong>ID:</strong> {room.id}
                  </p>
                  <p>
                    <strong>Owner:</strong> {room.owner_display_name} (@{room.owner_username})
                  </p>
                  <p>
                    <strong>Members:</strong> {room.member_count}
                  </p>
                  <div className="row">
                    <button onClick={() => void openRoom(room)}>Open Room</button>
                    {room.is_owner && (
                      <button className="danger" onClick={() => void deleteRoom(room.id)}>
                        Delete
                      </button>
                    )}
                    {!room.is_owner && (
                      <button className="secondary" onClick={() => void leaveRoomMembership(room.id)}>
                        Leave Room
                      </button>
                    )}
                  </div>
                </article>
              ))
            )}
          </section>

          {banner && <p className="error-text">{banner}</p>}
        </main>
      </div>
    );
  }

  return (
    <div className="room-shell">
      <aside className="room-sidebar">
        <h2>{roomTitle}</h2>
        <p>
          <strong>Status:</strong> {socketStatus}
        </p>
        <p>
          <strong>Logged in:</strong> {user?.display_name}
        </p>
        <button className="secondary" onClick={leaveRoom}>
          Back to Dashboard
        </button>
        {activeRoom && !activeRoom.is_owner && (
          <button className="danger" onClick={() => void leaveRoomMembership(activeRoom.id)}>
            Leave Room Permanently
          </button>
        )}

        <div className="member-list">
          <h3>Members ({roomMembers.length})</h3>
          {roomMembers.map((member) => (
            <p key={member.id}>
              {member.display_name}
              {member.username ? ` (@${member.username})` : ""}
              {!member.public_key ? " (no key yet)" : ""}
            </p>
          ))}
        </div>
      </aside>

      <main className="room-main">
        <header className="chat-header">
          <div>
            <h2>{activeRoom?.name}</h2>
            <small>Room ID: {activeRoom?.id}</small>
          </div>
          <div className="row small-gap">
            <input
              ref={fileInputRef}
              type="file"
              className="hidden-file"
              onChange={(event) => {
                void handleFilePicked(event);
              }}
            />
            <button className="secondary" onClick={() => fileInputRef.current?.click()}>
              Attach File
            </button>
          </div>
        </header>

        <section className="message-stream">
          {messages.length === 0 ? (
            <p className="muted centered-text">No messages yet. Start an encrypted conversation.</p>
          ) : (
            messages.map((message) => (
              <article
                key={message.id}
                className={`message ${message.own ? "outgoing" : "incoming"} ${
                  message.type === "system" ? "system" : ""
                } ${message.type === "error" ? "error" : ""}`}
              >
                <div className="message-head">
                  <strong>{message.sender}</strong>
                  <small>{new Date(message.timestamp).toLocaleTimeString()}</small>
                </div>
                <p>{message.content}</p>
              </article>
            ))
          )}
          <div ref={messageEndRef} />
        </section>

        <footer className="composer">
          <div className="emoji-tools">
            <button
              className="secondary emoji-trigger"
              onClick={() => setEmojiOpen((prev) => !prev)}
              aria-label="Toggle emoji picker"
            >
              🙂
            </button>
            {emojiOpen && (
              <div className="emoji-panel">
                {QUICK_EMOJIS.map((emoji) => (
                  <button
                    key={emoji}
                    className="emoji-btn"
                    onClick={() => appendEmoji(emoji)}
                    aria-label={`Insert ${emoji}`}
                  >
                    {emoji}
                  </button>
                ))}
              </div>
            )}
          </div>
          <input
            value={messageInput}
            onChange={(event) => setMessageInput(event.target.value)}
            placeholder="Type encrypted message..."
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                void sendMessage();
              }
            }}
          />
          <button onClick={() => void sendMessage()}>Send</button>
        </footer>

        {banner && <p className="error-text">{banner}</p>}
      </main>
    </div>
  );
}

export default App;
