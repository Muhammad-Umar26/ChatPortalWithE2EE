import { useEffect, useMemo, useRef, useState } from "react"
import {
  aesDecrypt,
  aesDecryptBytes,
  aesEncrypt,
  aesEncryptBytes,
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
} from "./crypto"

const runtimeHttpProtocol = window.location.protocol === "https:" ? "https" : "http"
const runtimeWsProtocol = window.location.protocol === "https:" ? "wss" : "ws"
const runtimeHost = window.location.hostname
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || `${runtimeHttpProtocol}://${runtimeHost}:8000`
const WS_BASE_URL = import.meta.env.VITE_WS_BASE_URL || `${runtimeWsProtocol}://${runtimeHost}:8000/ws`
const TOKEN_STORAGE_KEY = "chat_portal_token"
const USER_STORAGE_KEY = "chat_portal_user"
const KEY_STORAGE_PREFIX = "chat_portal_e2ee_keys_v1"
const PRESENCE_PING_INTERVAL_MS = 25_000
const SOCKET_NO_RECONNECT_CODES = new Set([4002, 4003, 4004, 4403, 4404])

function parseStoredUser() {
  const raw = localStorage.getItem(USER_STORAGE_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}

function safeJsonParse(text) {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

function buildErrorMessage(error) {
  if (!error) return "Unknown error"
  return error.message || "Unknown error"
}

function buildFullEmojiCatalog() {
  const list = []
  const seen = new Set()
  const addEmoji = (emoji) => {
    if (!emoji || seen.has(emoji)) return
    seen.add(emoji)
    list.push(emoji)
  }

  try {
    const emojiPresentationMatcher = /\p{Emoji_Presentation}/u
    const emojiComponentMatcher = /\p{Emoji_Component}/u
    const ranges = [
      [0x1f300, 0x1f5ff],
      [0x1f600, 0x1f64f],
      [0x1f680, 0x1f6ff],
      [0x1f900, 0x1f9ff],
      [0x1fa70, 0x1faff],
      [0x2600, 0x26ff],
      [0x2700, 0x27bf]
    ]
    for (const [start, end] of ranges) {
      for (let cp = start; cp <= end; cp += 1) {
        const emoji = String.fromCodePoint(cp)
        if (emojiComponentMatcher.test(emoji)) continue
        if (emojiPresentationMatcher.test(emoji)) {
          addEmoji(emoji)
        }
      }
    }
  } catch {
    // Browser fallback handled below.
  }

  ;[
    "😀",
    "😃",
    "😄",
    "😁",
    "😆",
    "😅",
    "😂",
    "🤣",
    "😊",
    "🙂",
    "😉",
    "😍",
    "😘",
    "😎",
    "🤔",
    "😴",
    "😢",
    "😭",
    "😡",
    "🥳",
    "😇",
    "🤝",
    "👍",
    "👏",
    "🙏",
    "❤️",
    "🔥",
    "🎉",
    "✨",
    "🫶",
    "🫡",
    "🏳️‍🌈",
    "🏳️‍⚧️",
    "🇵🇰",
    "🇺🇸",
    "🇬🇧",
    "🇦🇪",
    "🇮🇳",
    "🇨🇦",
    "❤️‍🔥",
    "❤️‍🩹",
    "🧑‍💻",
    "👨‍💻",
    "👩‍💻",
    "🧑‍🚀",
    "👨‍🚀",
    "👩‍🚀",
    "🧑‍🎓",
    "👨‍🎓",
    "👩‍🎓",
    "🧑‍⚕️",
    "👨‍⚕️",
    "👩‍⚕️",
    "🧑‍🏫",
    "👨‍🏫",
    "👩‍🏫"
  ].forEach(addEmoji)

  return list
}

const ALL_EMOJIS = buildFullEmojiCatalog()

function App() {
  const [booting, setBooting] = useState(true)
  const [view, setView] = useState("landing")
  const [authMode, setAuthMode] = useState("login")
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_STORAGE_KEY) || "")
  const [user, setUser] = useState(() => parseStoredUser())
  const [banner, setBanner] = useState("")

  const [authForm, setAuthForm] = useState({
    username: "",
    password: "",
    displayName: ""
  })
  const [authLoading, setAuthLoading] = useState(false)

  const [rooms, setRooms] = useState([])
  const [roomLoading, setRoomLoading] = useState(false)
  const [createRoomName, setCreateRoomName] = useState("")
  const [joinRoomId, setJoinRoomId] = useState("")

  const [activeRoom, setActiveRoom] = useState(null)
  const [socketStatus, setSocketStatus] = useState("Disconnected")
  const [roomMembers, setRoomMembers] = useState([])
  const [messages, setMessages] = useState([])
  const [messageInput, setMessageInput] = useState("")
  const [emojiOpen, setEmojiOpen] = useState(false)
  const [ownerLeaveTargetId, setOwnerLeaveTargetId] = useState("")
  const [downloadingFileIds, setDownloadingFileIds] = useState({})

  const wsRef = useRef(null)
  const reconnectTimerRef = useRef(null)
  const shouldReconnectRef = useRef(false)
  const activeRoomRef = useRef(null)
  const keyPairRef = useRef(null)
  const publicKeyBase64Ref = useRef("")
  const memberPublicKeysRef = useRef(new Map())
  const messageEndRef = useRef(null)
  const fileInputRef = useRef(null)

  const roomTitle = useMemo(() => {
    if (!activeRoom) return ""
    return `${activeRoom.name} (${activeRoom.id})`
  }, [activeRoom])

  const ownerTransferCandidates = useMemo(() => {
    if (!activeRoom?.is_owner) return []
    return roomMembers.filter((member) => member.id !== user?.id)
  }, [activeRoom?.is_owner, roomMembers, user?.id])

  useEffect(() => {
    activeRoomRef.current = activeRoom
  }, [activeRoom])

  useEffect(() => {
    if (messageEndRef.current) {
      messageEndRef.current.scrollIntoView({ behavior: "smooth", block: "end" })
    }
  }, [messages])

  useEffect(() => {
    if (!activeRoom?.is_owner) {
      setOwnerLeaveTargetId("")
      return
    }
    const hasCurrent = ownerTransferCandidates.some((member) => String(member.id) === ownerLeaveTargetId)
    if (!hasCurrent) {
      setOwnerLeaveTargetId(ownerTransferCandidates[0] ? String(ownerTransferCandidates[0].id) : "")
    }
  }, [activeRoom?.is_owner, ownerTransferCandidates, ownerLeaveTargetId])

  useEffect(() => {
    document.body.classList.toggle("room-active", view === "room")
    return () => {
      document.body.classList.remove("room-active")
    }
  }, [view])

  useEffect(() => {
    return () => {
      closeSocketConnection(false)
    }
  }, [])

  useEffect(() => {
    let cancelled = false

    async function bootstrapSession() {
      if (!token || !user) {
        setBooting(false)
        setView("landing")
        return
      }

      try {
        const me = await apiRequest("/auth/me", { authToken: token })
        if (cancelled) return
        setUser(me.user)
        await ensureUserKeys(token, me.user)
        await loadRooms(token)
        setView("dashboard")
      } catch {
        if (cancelled) return
        clearSession()
        setView("landing")
      } finally {
        if (!cancelled) {
          setBooting(false)
        }
      }
    }

    void bootstrapSession()
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!token || !user?.id) {
      return undefined
    }

    const sendPresencePing = async () => {
      try {
        await apiRequest("/auth/ping", { method: "POST", authToken: token })
        if (view === "dashboard") {
          await loadRooms(token)
        }
      } catch {
        // Keep UI responsive while temporary network issues recover.
      }
    }

    void sendPresencePing()
    const timer = setInterval(() => {
      void sendPresencePing()
    }, PRESENCE_PING_INTERVAL_MS)

    return () => {
      clearInterval(timer)
    }
  }, [token, user?.id, view])

  async function apiRequest(path, { method = "GET", body, authToken = token } = {}) {
    const headers = {}
    const isFormData = typeof FormData !== "undefined" && body instanceof FormData
    if (body && !isFormData) headers["Content-Type"] = "application/json"
    if (authToken) headers.Authorization = `Bearer ${authToken}`

    let response
    try {
      response = await fetch(`${API_BASE_URL}${path}`, {
        method,
        headers,
        body: body ? (isFormData ? body : JSON.stringify(body)) : undefined
      })
    } catch {
      throw new Error(
        `Cannot reach backend at ${API_BASE_URL}. Start FastAPI and ensure CORS allows this frontend origin.`
      )
    }

    const isJson = (response.headers.get("content-type") || "").includes("application/json")
    const data = isJson ? await response.json() : null

    if (!response.ok) {
      const detail = data?.detail || `Request failed (${response.status})`
      const error = new Error(detail)
      error.status = response.status
      throw error
    }

    return data
  }

  async function apiDownloadBinary(path, { authToken = token } = {}) {
    const headers = {}
    if (authToken) headers.Authorization = `Bearer ${authToken}`

    let response
    try {
      response = await fetch(`${API_BASE_URL}${path}`, {
        method: "GET",
        headers
      })
    } catch {
      throw new Error(`Cannot reach backend at ${API_BASE_URL} to download file`)
    }

    if (!response.ok) {
      let detail = `Request failed (${response.status})`
      try {
        const maybeJson = await response.json()
        if (maybeJson?.detail) detail = maybeJson.detail
      } catch {
        // Ignore parsing fallback.
      }
      throw new Error(detail)
    }

    const binary = await response.arrayBuffer()
    return new Uint8Array(binary)
  }

  async function ensureUserKeys(authToken, authUser) {
    try {
      const storageKey = `${KEY_STORAGE_PREFIX}:${authUser.id}`
      let keyPair = null
      const rawKeys = localStorage.getItem(storageKey)

      if (rawKeys) {
        try {
          const parsed = JSON.parse(rawKeys)
          keyPair = await importKeyPairFromJwk(parsed.publicJwk, parsed.privateJwk)
        } catch {
          localStorage.removeItem(storageKey)
        }
      }

      if (!keyPair) {
        keyPair = await generateRsaKeyPair()
        const jwkBundle = await exportKeyPairToJwk(keyPair)
        localStorage.setItem(storageKey, JSON.stringify(jwkBundle))
      }

      keyPairRef.current = keyPair
      publicKeyBase64Ref.current = await exportPublicKeyToBase64(keyPair.publicKey)
      await apiRequest("/auth/public-key", {
        method: "PUT",
        authToken,
        body: { public_key: publicKeyBase64Ref.current }
      })
    } catch {
      throw new Error(
        "Unable to initialize E2EE keys on this browser. Refresh and retry, then run npm install in frontend if dependencies were updated."
      )
    }
  }

  function storeSession(sessionToken, sessionUser) {
    localStorage.setItem(TOKEN_STORAGE_KEY, sessionToken)
    localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(sessionUser))
    setToken(sessionToken)
    setUser(sessionUser)
  }

  function closeSocketConnection(allowReconnect) {
    shouldReconnectRef.current = allowReconnect
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }
    const socket = wsRef.current
    wsRef.current = null
    if (socket && socket.readyState <= 1) {
      socket.close(1000, "Closing socket")
    }
  }

  function leaveRoom({ keepBanner = false, bannerMessage = "" } = {}) {
    closeSocketConnection(false)
    setActiveRoom(null)
    setRoomMembers([])
    setMessages([])
    setMessageInput("")
    setEmojiOpen(false)
    setView("dashboard")
    setSocketStatus("Disconnected")
    if (keepBanner) {
      setBanner(bannerMessage)
    } else {
      setBanner("")
    }
  }

  function clearSession() {
    leaveRoom()
    localStorage.removeItem(TOKEN_STORAGE_KEY)
    localStorage.removeItem(USER_STORAGE_KEY)
    setToken("")
    setUser(null)
    setRooms([])
    memberPublicKeysRef.current = new Map()
    keyPairRef.current = null
    publicKeyBase64Ref.current = ""
    setView("landing")
  }

  async function loadRooms(authToken = token) {
    const data = await apiRequest("/rooms", { authToken })
    setRooms(data.rooms || [])
  }

  function appendSystemMessage(content) {
    setMessages((prev) => [
      ...prev,
      {
        id: `sys-${Date.now()}-${Math.random()}`,
        messageId: null,
        sender: "System",
        senderId: 0,
        content,
        timestamp: new Date().toISOString(),
        type: "system",
        own: false
      }
    ])
  }

  function formatOnlineStatus(packet) {
    const fallback = Math.max((Number(packet?.onlineCount) || 0) - 1, 0)
    const parsedPeerCount = Number(packet?.peerOnlineCount)
    const peersOnline = Number.isFinite(parsedPeerCount) ? Math.max(parsedPeerCount, 0) : fallback
    return `Connected (${peersOnline} online)`
  }

  async function hydratePacketToMessage(packet, fallbackMeta = {}) {
    if (!packet || typeof packet !== "object") {
      return null
    }

    if (packet.type === "message_deleted") {
      const senderId = Number(packet.senderId ?? fallbackMeta?.sender?.id ?? 0)
      const senderName =
        senderId === user?.id
          ? "You"
          : packet.sender || fallbackMeta?.sender?.display_name || fallbackMeta?.sender?.username || "Unknown"
      const resolvedMessageId = Number(packet.messageId ?? fallbackMeta.id ?? 0) || null
      return {
        id: resolvedMessageId ? `msg-${resolvedMessageId}` : `msg-del-${Date.now()}-${Math.random()}`,
        messageId: resolvedMessageId,
        senderId,
        sender: senderName,
        content: "This message was deleted",
        timestamp: packet.sentAt || fallbackMeta.created_at || new Date().toISOString(),
        type: "deleted",
        own: senderId === user?.id
      }
    }

    if (packet.type === "chat") {
      const senderId = Number(packet.senderId ?? fallbackMeta?.sender?.id ?? 0)
      const senderName =
        packet.sender ||
        fallbackMeta?.sender?.display_name ||
        fallbackMeta?.sender?.username ||
        "Unknown"
      const senderUsername = packet.senderUsername || fallbackMeta?.sender?.username || ""
      const resolvedMessageId = Number(packet.messageId ?? fallbackMeta.id ?? 0) || null

      const wrappedAesKey = packet?.encryptedKeys?.[String(user?.id)] ?? packet?.encryptedKeys?.[user?.id]
      const timestamp = packet.sentAt || fallbackMeta.created_at || new Date().toISOString()
      const resolvedSender =
        senderId === user?.id
          ? "You"
          : senderUsername
            ? `${senderName} (@${senderUsername})`
            : senderName
      if (!keyPairRef.current?.privateKey) {
        return {
          id: resolvedMessageId ? `msg-${resolvedMessageId}` : `msg-${Date.now()}-${Math.random()}`,
          messageId: resolvedMessageId,
          senderId,
          sender: resolvedSender,
          content: "[Encrypted message unavailable: local private key not found on this browser.]",
          timestamp,
          type: "error",
          own: senderId === user?.id
        }
      }

      if (!wrappedAesKey) {
        const missingKeyMessage =
          senderId === user?.id
            ? "[Encrypted with a previous key pair for this account. Re-login on the original browser/protocol to decrypt.]"
            : "[Encrypted message unavailable for your current key.]"
        return {
          id: resolvedMessageId ? `msg-${resolvedMessageId}` : `msg-${Date.now()}-${Math.random()}`,
          messageId: resolvedMessageId,
          senderId,
          sender: resolvedSender,
          content: missingKeyMessage,
          timestamp,
          type: "error",
          own: senderId === user?.id
        }
      }

      let content = ""
      let decryptFailed = false
      try {
        const aesRawBase64 = await decryptWithPrivateKey(keyPairRef.current.privateKey, wrappedAesKey)
        const aesKey = await importAesRawFromBase64(aesRawBase64)
        content = await aesDecrypt(aesKey, packet.iv, packet.ciphertext)
      } catch {
        decryptFailed = true
        content = "[Unable to decrypt this message]"
      }

      return {
        id: resolvedMessageId ? `msg-${resolvedMessageId}` : `msg-${Date.now()}-${Math.random()}`,
        messageId: resolvedMessageId,
        senderId,
        sender: resolvedSender,
        content,
        timestamp,
        type: decryptFailed ? "error" : "chat",
        own: senderId === user?.id
      }
    }

    if (packet.type === "file_shared") {
      const senderId = Number(packet.senderId ?? fallbackMeta?.sender?.id ?? 0)
      const senderName =
        packet.sender ||
        fallbackMeta?.sender?.display_name ||
        fallbackMeta?.sender?.username ||
        "Unknown"
      const senderUsername = packet.senderUsername || fallbackMeta?.sender?.username || ""
      const resolvedMessageId = Number(packet.messageId ?? fallbackMeta.id ?? 0) || null
      const fileId = Number(packet.fileId ?? 0)
      if (!fileId) {
        return null
      }
      return {
        id: resolvedMessageId ? `msg-${resolvedMessageId}` : `file-${fileId}-${Date.now()}-${Math.random()}`,
        messageId: resolvedMessageId,
        senderId,
        sender:
          senderId === user?.id
            ? "You"
            : senderUsername
              ? `${senderName} (@${senderUsername})`
              : senderName,
        content: `Shared encrypted file: ${packet.fileName || "file"}`,
        timestamp: packet.sentAt || fallbackMeta.created_at || new Date().toISOString(),
        type: "file",
        own: senderId === user?.id,
        fileId,
        fileName: packet.fileName || "encrypted-file.bin",
        fileType: packet.fileType || "application/octet-stream",
        fileSize: Number(packet.fileSize || 0),
        fileIv: packet.iv || "",
        encryptedKeys: packet.encryptedKeys || {}
      }
    }

    if (packet.type === "member_joined") {
      return {
        id: `sys-join-${Date.now()}-${Math.random()}`,
        messageId: null,
        sender: "System",
        senderId: 0,
        content: `${packet.sender} joined the room`,
        timestamp: packet.sentAt || new Date().toISOString(),
        type: "system",
        own: false
      }
    }

    if (packet.type === "member_left") {
      const content = packet.removedBy
        ? `${packet.sender} was removed by ${packet.removedBy}`
        : `${packet.sender} left the room`
      return {
        id: `sys-left-${Date.now()}-${Math.random()}`,
        messageId: null,
        sender: "System",
        senderId: 0,
        content,
        timestamp: packet.sentAt || new Date().toISOString(),
        type: "system",
        own: false
      }
    }

    if (packet.type === "owner_transferred") {
      return {
        id: `sys-owner-${Date.now()}-${Math.random()}`,
        messageId: null,
        sender: "System",
        senderId: 0,
        content: `Ownership transferred from ${packet.previousOwner} to ${packet.newOwner}`,
        timestamp: packet.sentAt || new Date().toISOString(),
        type: "system",
        own: false
      }
    }

    if (packet.type === "file-intent") {
      return {
        id: `sys-file-${Date.now()}-${Math.random()}`,
        messageId: null,
        sender: "System",
        senderId: 0,
        content: `${packet.sender} wants to send file: ${packet.fileName} (${packet.fileSize} bytes). FTP module pending integration.`,
        timestamp: packet.sentAt || new Date().toISOString(),
        type: "system",
        own: false
      }
    }

    return null
  }

  async function handleRealtimePacket(roomId, packet) {
    if (!packet || typeof packet !== "object") return
    if (packet.roomId && packet.roomId !== roomId) return

    if (packet.type === "server_ack") {
      setSocketStatus(formatOnlineStatus(packet))
      return
    }

    if (packet.type === "online_count") {
      setSocketStatus(formatOnlineStatus(packet))
      setRooms((prev) =>
        prev.map((room) =>
          room.id === roomId
            ? { ...room, online_member_count: Number(packet.onlineCount) || room.online_member_count || 0 }
            : room
        )
      )
      setActiveRoom((prev) =>
        prev && prev.id === roomId
          ? { ...prev, online_member_count: Number(packet.onlineCount) || prev.online_member_count || 0 }
          : prev
      )
      return
    }

    if (packet.type === "announce" && packet.senderId && packet.publicKey) {
      memberPublicKeysRef.current.set(String(packet.senderId), packet.publicKey)
      setRoomMembers((prev) => {
        const existing = prev.find((member) => member.id === packet.senderId)
        if (!existing) {
          return [
            ...prev,
            {
              id: packet.senderId,
              username: packet.senderUsername || "",
              display_name: packet.sender || "Unknown",
              public_key: packet.publicKey,
              is_online: true
            }
          ]
        }
        return prev.map((member) =>
          member.id === packet.senderId
            ? { ...member, public_key: packet.publicKey, is_online: true }
            : member
        )
      })
      return
    }

    if (packet.type === "member_joined") {
      setRoomMembers((prev) => {
        if (prev.some((member) => member.id === packet.senderId)) {
          return prev
        }
        return [
          ...prev,
          {
            id: packet.senderId,
            username: packet.senderUsername || "",
            display_name: packet.sender || "Unknown",
            public_key: null,
            is_online: true
          }
        ]
      })
      setRooms((prev) =>
        prev.map((room) =>
          room.id === roomId ? { ...room, member_count: Number(room.member_count || 0) + 1 } : room
        )
      )
      if (packet.senderId !== user?.id) {
        appendSystemMessage(`${packet.sender} joined the room`)
      }
      return
    }

    if (packet.type === "member_left") {
      memberPublicKeysRef.current.delete(String(packet.senderId))
      setRoomMembers((prev) => prev.filter((member) => member.id !== packet.senderId))
      setRooms((prev) =>
        prev.map((room) =>
          room.id === roomId
            ? { ...room, member_count: Math.max(Number(room.member_count || 1) - 1, 0) }
            : room
        )
      )
      if (packet.senderId !== user?.id) {
        appendSystemMessage(packet.removedBy ? `${packet.sender} was removed by ${packet.removedBy}` : `${packet.sender} left the room`)
      }
      return
    }

    if (packet.type === "owner_transferred") {
      setActiveRoom((prev) =>
        prev && prev.id === roomId
          ? {
              ...prev,
              owner_id: packet.newOwnerId,
              owner_display_name: packet.newOwner,
              owner_username: packet.newOwnerUsername,
              is_owner: packet.newOwnerId === user?.id
            }
          : prev
      )
      setRooms((prev) =>
        prev.map((room) =>
          room.id === roomId
            ? {
                ...room,
                owner_id: packet.newOwnerId,
                owner_display_name: packet.newOwner,
                owner_username: packet.newOwnerUsername,
                is_owner: packet.newOwnerId === user?.id
              }
            : room
        )
      )
      appendSystemMessage(`Ownership transferred from ${packet.previousOwner} to ${packet.newOwner}`)
      return
    }

    if (packet.type === "message_deleted") {
      const deletedMessageId = Number(packet.messageId || 0)
      if (!deletedMessageId) return
      setMessages((prev) => {
        let found = false
        const updated = prev.map((message) => {
          if (message.messageId === deletedMessageId) {
            found = true
            return {
              ...message,
              content: "This message was deleted",
              type: "deleted"
            }
          }
          return message
        })
        if (found) return updated
        return [
          ...updated,
          {
            id: `msg-${deletedMessageId}`,
            messageId: deletedMessageId,
            senderId: Number(packet.senderId || 0),
            sender: packet.sender || "Unknown",
            content: "This message was deleted",
            timestamp: packet.sentAt || new Date().toISOString(),
            type: "deleted",
            own: Number(packet.senderId || 0) === user?.id
          }
        ]
      })
      return
    }

    if (packet.type === "room_deleted") {
      leaveRoom({
        keepBanner: true,
        bannerMessage: `Room was deleted by ${packet.deletedBy}`
      })
      await loadRooms()
      return
    }

    const nextMessage = await hydratePacketToMessage(packet)
    if (nextMessage) {
      setMessages((prev) => [...prev, nextMessage])
    }
  }

  function connectRoomSocket(roomId) {
    if (!token || !roomId) return

    closeSocketConnection(false)
    shouldReconnectRef.current = true
    setSocketStatus("Connecting...")

    const socket = new WebSocket(`${WS_BASE_URL}/${encodeURIComponent(roomId)}?token=${encodeURIComponent(token)}`)
    wsRef.current = socket

    socket.onopen = () => {
      setSocketStatus("Connected (syncing online status...)")
      const announcePacket = {
        type: "announce",
        roomId,
        publicKey: publicKeyBase64Ref.current,
        sentAt: new Date().toISOString()
      }
      socket.send(JSON.stringify(announcePacket))
    }

    socket.onmessage = (event) => {
      const packet = safeJsonParse(event.data)
      if (!packet) return
      void handleRealtimePacket(roomId, packet)
    }

    socket.onerror = () => {
      setSocketStatus("Socket error")
    }

    socket.onclose = (event) => {
      wsRef.current = null
      const currentRoom = activeRoomRef.current

      if (SOCKET_NO_RECONNECT_CODES.has(event.code)) {
        shouldReconnectRef.current = false
        leaveRoom({
          keepBanner: true,
          bannerMessage: event.reason || "You no longer have access to this room."
        })
        void loadRooms()
        return
      }

      setSocketStatus("Disconnected")
      if (shouldReconnectRef.current && currentRoom?.id === roomId) {
        reconnectTimerRef.current = setTimeout(() => {
          connectRoomSocket(roomId)
        }, 1500)
      }
    }
  }

  async function openRoom(room) {
    setBanner("")
    setActiveRoom(room)
    setMessages([])
    setRoomMembers([])
    setEmojiOpen(false)
    memberPublicKeysRef.current = new Map()
    setView("room")
    const peersOnline = Math.max((Number(room.online_member_count) || 0) - 1, 0)
    setSocketStatus(`Loading... (${peersOnline} online)`)

    try {
      const [memberData, messageData] = await Promise.all([
        apiRequest(`/rooms/${room.id}/members`),
        apiRequest(`/rooms/${room.id}/messages?limit=200`)
      ])

      const members = memberData.members || []
      setRoomMembers(members)

      const memberKeyMap = new Map()
      for (const member of members) {
        if (member.public_key) {
          memberKeyMap.set(String(member.id), member.public_key)
        }
      }
      if (user?.id && publicKeyBase64Ref.current) {
        memberKeyMap.set(String(user.id), publicKeyBase64Ref.current)
      }
      memberPublicKeysRef.current = memberKeyMap

      const hydrated = []
      for (const rawMessage of messageData.messages || []) {
        const built = await hydratePacketToMessage(rawMessage.packet, rawMessage)
        if (built) {
          hydrated.push(built)
        }
      }
      setMessages(hydrated)
      connectRoomSocket(room.id)
    } catch (error) {
      setBanner(`Failed to open room: ${buildErrorMessage(error)}`)
      setView("dashboard")
      setActiveRoom(null)
      setSocketStatus("Disconnected")
    }
  }

  async function submitAuth(event) {
    event.preventDefault()
    setBanner("")
    setAuthLoading(true)

    try {
      const endpoint = authMode === "register" ? "/auth/register" : "/auth/login"
      const payload = {
        username: authForm.username.trim(),
        password: authForm.password
      }
      if (authMode === "register" && authForm.displayName.trim()) {
        payload.display_name = authForm.displayName.trim()
      }

      const data = await apiRequest(endpoint, { method: "POST", body: payload, authToken: "" })
      storeSession(data.token, data.user)
      await ensureUserKeys(data.token, data.user)
      await loadRooms(data.token)
      setAuthForm({ username: "", password: "", displayName: "" })
      setView("dashboard")
    } catch (error) {
      setBanner(buildErrorMessage(error))
    } finally {
      setAuthLoading(false)
    }
  }

  async function createRoom(event) {
    event.preventDefault()
    const roomName = createRoomName.trim()
    if (!roomName) return
    if (!window.confirm(`Create room "${roomName}"?`)) return
    setBanner("")

    try {
      setRoomLoading(true)
      const response = await apiRequest("/rooms", {
        method: "POST",
        body: { name: roomName }
      })
      setCreateRoomName("")
      await loadRooms()
      await openRoom(response.room)
    } catch (error) {
      setBanner(buildErrorMessage(error))
    } finally {
      setRoomLoading(false)
    }
  }

  async function joinRoom(event) {
    event.preventDefault()
    const roomId = joinRoomId.trim()
    if (!roomId) return
    if (!window.confirm(`Join room "${roomId}"?`)) return
    setBanner("")

    try {
      setRoomLoading(true)
      const response = await apiRequest(`/rooms/${roomId}/join`, { method: "POST" })
      setJoinRoomId("")
      await loadRooms()
      await openRoom(response.room)
    } catch (error) {
      setBanner(buildErrorMessage(error))
    } finally {
      setRoomLoading(false)
    }
  }

  async function deleteRoom(roomId) {
    if (!window.confirm("Delete this room permanently for all members?")) return
    setBanner("")
    try {
      await apiRequest(`/rooms/${roomId}`, { method: "DELETE" })
      if (activeRoomRef.current?.id === roomId) {
        leaveRoom()
      }
      await loadRooms()
    } catch (error) {
      setBanner(buildErrorMessage(error))
    }
  }

  async function leaveRoomMembership(roomId) {
    if (!window.confirm("Leave this room permanently? You can join again later using Room ID.")) return
    setBanner("")
    try {
      if (activeRoomRef.current?.id === roomId) {
        closeSocketConnection(false)
      }
      await apiRequest(`/rooms/${roomId}/leave`, { method: "POST" })
      if (activeRoomRef.current?.id === roomId) {
        leaveRoom()
      }
      await loadRooms()
    } catch (error) {
      setBanner(buildErrorMessage(error))
    }
  }

  async function removeMemberFromRoom(member) {
    if (!activeRoom) return
    if (!window.confirm(`Remove ${member.display_name} from this room?`)) return
    setBanner("")
    try {
      await apiRequest(`/rooms/${activeRoom.id}/remove-member`, {
        method: "POST",
        body: { user_id: member.id }
      })
    } catch (error) {
      setBanner(buildErrorMessage(error))
    }
  }

  async function transferOwnershipAndLeave() {
    if (!activeRoom || !activeRoom.is_owner) return
    const nextOwnerId = Number(ownerLeaveTargetId)
    if (!nextOwnerId) {
      setBanner("Select a member to transfer ownership before leaving.")
      return
    }
    const nextOwner = ownerTransferCandidates.find((member) => member.id === nextOwnerId)
    if (!nextOwner) {
      setBanner("Selected owner is no longer valid. Please re-select.")
      return
    }
    if (
      !window.confirm(
        `Transfer ownership to ${nextOwner.display_name} and leave this room permanently?`
      )
    ) {
      return
    }

    setBanner("")
    try {
      await apiRequest(`/rooms/${activeRoom.id}/owner-leave`, {
        method: "POST",
        body: { new_owner_id: nextOwnerId }
      })
      leaveRoom({
        keepBanner: true,
        bannerMessage: `Ownership transferred to ${nextOwner.display_name}. You left the room.`
      })
      await loadRooms()
    } catch (error) {
      setBanner(buildErrorMessage(error))
    }
  }

  async function deleteOwnMessage(messageId) {
    if (!activeRoom || !messageId) return
    if (!window.confirm("Delete this message for everyone in this room?")) return
    setBanner("")
    try {
      await apiRequest(`/rooms/${activeRoom.id}/messages/${messageId}/delete`, { method: "POST" })
      setMessages((prev) =>
        prev.map((message) =>
          message.messageId === messageId
            ? { ...message, content: "This message was deleted", type: "deleted" }
            : message
        )
      )
    } catch (error) {
      setBanner(buildErrorMessage(error))
    }
  }

  async function downloadSharedFile(message) {
    if (!message?.fileId || !message?.fileIv) {
      setBanner("Invalid file metadata. Please ask sender to share again.")
      return
    }
    if (!keyPairRef.current?.privateKey) {
      setBanner("Your private key is unavailable on this browser. Cannot decrypt file.")
      return
    }

    const wrappedAesKey =
      message?.encryptedKeys?.[String(user?.id)] ?? message?.encryptedKeys?.[user?.id] ?? null
    if (!wrappedAesKey) {
      setBanner("This encrypted file is not available for your current key.")
      return
    }

    setBanner("")
    setDownloadingFileIds((prev) => ({ ...prev, [message.fileId]: true }))
    try {
      const aesRawBase64 = await decryptWithPrivateKey(keyPairRef.current.privateKey, wrappedAesKey)
      const aesKey = await importAesRawFromBase64(aesRawBase64)
      const encryptedBytes = await apiDownloadBinary(`/ftp/download/${message.fileId}`)
      const decryptedBytes = await aesDecryptBytes(aesKey, message.fileIv, encryptedBytes)

      const fileName = message.fileName || `file-${message.fileId}`
      const mimeType = message.fileType || "application/octet-stream"
      const blob = new Blob([decryptedBytes], { type: mimeType })
      const blobUrl = URL.createObjectURL(blob)
      const anchor = document.createElement("a")
      anchor.href = blobUrl
      anchor.download = fileName
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      URL.revokeObjectURL(blobUrl)
    } catch (error) {
      setBanner(`File download/decryption failed: ${buildErrorMessage(error)}`)
    } finally {
      setDownloadingFileIds((prev) => {
        const next = { ...prev }
        delete next[message.fileId]
        return next
      })
    }
  }

  async function sendMessage() {
    const plaintext = messageInput.trim()
    if (!plaintext || !activeRoom || !user) return

    const socket = wsRef.current
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      setBanner("WebSocket is disconnected. Wait for reconnect and try again.")
      return
    }

    try {
      const recipientKeyMap = new Map(memberPublicKeysRef.current)
      if (publicKeyBase64Ref.current) {
        recipientKeyMap.set(String(user.id), publicKeyBase64Ref.current)
      }

      if (recipientKeyMap.size === 0) {
        setBanner("No public keys found in this room yet.")
        return
      }

      const missingKeys = roomMembers.filter((member) => !recipientKeyMap.get(String(member.id)))
      if (missingKeys.length > 0) {
        appendSystemMessage(
          `Warning: ${missingKeys.length} room member(s) have no public key yet and may not decrypt this message.`
        )
      }

      const aesKey = await generateAesKey()
      const aesRawBase64 = await exportAesRawToBase64(aesKey)
      const encryptedKeys = {}

      for (const [recipientId, recipientPublicKeyBase64] of recipientKeyMap.entries()) {
        const recipientPublicKey = await importPublicKeyFromBase64(recipientPublicKeyBase64)
        encryptedKeys[recipientId] = await encryptWithPublicKey(recipientPublicKey, aesRawBase64)
      }

      const { iv, ciphertext } = await aesEncrypt(aesKey, plaintext)
      socket.send(
        JSON.stringify({
          type: "chat",
          roomId: activeRoom.id,
          encryptedKeys,
          iv,
          ciphertext,
          sentAt: new Date().toISOString()
        })
      )

      setMessageInput("")
      setEmojiOpen(false)
    } catch (error) {
      appendSystemMessage(`Message send failed: ${buildErrorMessage(error)}`)
    }
  }

  function appendEmoji(emoji) {
    setMessageInput((prev) => `${prev}${emoji}`)
  }

  async function handleFilePicked(event) {
    const file = event.target.files?.[0]
    event.target.value = ""
    if (!file || !activeRoom || !user) return

    const socket = wsRef.current
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      setBanner("WebSocket is disconnected. Reconnect to share files securely.")
      return
    }

    try {
      const recipientKeyMap = new Map(memberPublicKeysRef.current)
      if (publicKeyBase64Ref.current) {
        recipientKeyMap.set(String(user.id), publicKeyBase64Ref.current)
      }
      if (recipientKeyMap.size === 0) {
        setBanner("No recipient public keys available in this room yet.")
        return
      }

      const aesKey = await generateAesKey()
      const aesRawBase64 = await exportAesRawToBase64(aesKey)
      const encryptedKeys = {}
      for (const [recipientId, recipientPublicKeyBase64] of recipientKeyMap.entries()) {
        const recipientPublicKey = await importPublicKeyFromBase64(recipientPublicKeyBase64)
        encryptedKeys[recipientId] = await encryptWithPublicKey(recipientPublicKey, aesRawBase64)
      }

      const rawBytes = new Uint8Array(await file.arrayBuffer())
      const { iv, ciphertextBytes } = await aesEncryptBytes(aesKey, rawBytes)

      const formData = new FormData()
      formData.append("room_id", activeRoom.id)
      formData.append(
        "file",
        new File([ciphertextBytes], `${file.name}.enc`, {
          type: "application/octet-stream"
        })
      )
      const uploadResponse = await apiRequest("/ftp/upload", {
        method: "POST",
        body: formData
      })

      socket.send(
        JSON.stringify({
          type: "file_shared",
          roomId: activeRoom.id,
          fileId: Number(uploadResponse.file_id),
          fileName: file.name,
          fileSize: file.size,
          fileType: file.type || "application/octet-stream",
          encryptedKeys,
          iv,
          sentAt: new Date().toISOString()
        })
      )
    } catch (error) {
      appendSystemMessage(`File share failed: ${buildErrorMessage(error)}`)
    }
  }

  async function signOut() {
    try {
      if (token) {
        await apiRequest("/auth/logout", { method: "POST", authToken: token })
      }
    } catch {
      // Local logout still proceeds even if backend logout call fails.
    }
    clearSession()
  }

  if (booting) {
    return (
      <div className="screen centered">
        <div className="card">
          <h1>Chat Portal</h1>
          <p>Loading your secure workspace...</p>
        </div>
      </div>
    )
  }

  if (view === "landing") {
    return (
      <div className="screen landing-screen">
        <header className="landing-nav">
          <div className="landing-brand">
            <div className="landing-brand-dot" />
            <strong>Chat Portal</strong>
          </div>
          <div className="row">
            <button
              onClick={() => {
                setAuthMode("login")
                setView("auth")
                setBanner("")
              }}
            >
              Login
            </button>
            <button
              className="secondary"
              onClick={() => {
                setAuthMode("register")
                setView("auth")
                setBanner("")
              }}
            >
              Register
            </button>
          </div>
        </header>

        <section className="card landing-hero">
          <div className="landing-hero-main">
            <p className="landing-kicker">Secure collaboration workspace</p>
            <h1>Modern encrypted room chat with clean, fast real-time UX</h1>
            <p className="landing-tagline">
              End-to-end encrypted multi-room chat built with FastAPI, WebSockets, and React. Designed for
              live demos, teamwork, and extensible networking coursework.
            </p>
            <div className="landing-quick-points">
              <span>End-to-end encrypted payloads</span>
              <span>Live room activity and presence</span>
              <span>Owner moderation controls</span>
            </div>
            <div className="row landing-actions">
              <button
                onClick={() => {
                  setAuthMode("register")
                  setView("auth")
                  setBanner("")
                }}
              >
                Get Started
              </button>
              <button
                className="secondary"
                onClick={() => {
                  setAuthMode("login")
                  setView("auth")
                  setBanner("")
                }}
              >
                I already have an account
              </button>
            </div>
          </div>
          <div className="landing-hero-stats">
            <section className="landing-feature-grid">
              <article className="card landing-feature-card">
                <h3>End-to-End Encryption</h3>
                <p>RSA key exchange and AES-GCM payload encryption handled on client devices.</p>
              </article>
              <article className="card landing-feature-card">
                <h3>Room Ownership Controls</h3>
                <p>Owner can remove members, transfer ownership, and moderate room membership cleanly.</p>
              </article>
              <article className="card landing-feature-card">
                <h3>Persistent History</h3>
                <p>Encrypted message packets and membership records are saved and loaded from database.</p>
              </article>
            </section>
          </div>
        </section>
      </div>
    )
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
          <div className="auth-links">
            <button
              className="link-button"
              onClick={() => setAuthMode((prev) => (prev === "login" ? "register" : "login"))}
            >
              {authMode === "login" ? "Need an account? Register" : "Already have an account? Login"}
            </button>
            <button className="link-button auth-home-link" onClick={() => setView("landing")}>
              Back to home
            </button>
          </div>
          {banner && <p className="error-text">{banner}</p>}
        </div>
      </div>
    )
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
          <button className="danger" onClick={() => void signOut()}>
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
              rooms.map((room) => {
                const peersOnline = Math.max((Number(room.online_member_count) || 0) - 1, 0)
                return (
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
                    <p>
                      <strong>Online now:</strong> {peersOnline} other member{peersOnline === 1 ? "" : "s"}
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
                )
              })
            )}
          </section>

          {banner && <p className="error-text">{banner}</p>}
        </main>
      </div>
    )
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
        <button className="secondary" onClick={() => leaveRoom()}>
          Back to Dashboard
        </button>

        {activeRoom?.is_owner ? (
          <div className="owner-transfer-panel">
            <h3>Owner controls</h3>
            {ownerTransferCandidates.length > 0 ? (
              <>
                <label htmlFor="ownerTransferSelect">Transfer ownership before leaving</label>
                <select
                  id="ownerTransferSelect"
                  value={ownerLeaveTargetId}
                  onChange={(event) => setOwnerLeaveTargetId(event.target.value)}
                >
                  {ownerTransferCandidates.map((member) => (
                    <option key={member.id} value={member.id}>
                      {member.display_name} {member.username ? `(@${member.username})` : ""}
                    </option>
                  ))}
                </select>
                <button className="danger" onClick={() => void transferOwnershipAndLeave()}>
                  Transfer & Leave Room
                </button>
              </>
            ) : (
              <p className="muted">
                You are the only member in this room. Delete the room if you want to close it.
              </p>
            )}
          </div>
        ) : (
          activeRoom && (
            <button className="danger" onClick={() => void leaveRoomMembership(activeRoom.id)}>
              Leave Room Permanently
            </button>
          )
        )}

        <div className="member-list">
          <h3>Members ({roomMembers.length})</h3>
          {roomMembers.map((member) => {
            const isOwnerMember = activeRoom?.owner_id === member.id
            const canRemove = activeRoom?.is_owner && member.id !== user?.id && !isOwnerMember
            return (
              <div key={member.id} className="member-row">
                <p className={member.is_online ? "member-online" : "member-offline"}>
                  {member.display_name}
                  {member.username ? ` (@${member.username})` : ""}
                  {isOwnerMember ? " • owner" : ""}
                  {member.is_online ? " • online" : ""}
                  {!member.public_key ? " (no key yet)" : ""}
                </p>
                {canRemove && (
                  <button className="link-button member-remove-btn" onClick={() => void removeMemberFromRoom(member)}>
                    Remove
                  </button>
                )}
              </div>
            )
          })}
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
                void handleFilePicked(event)
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
                } ${message.type === "error" ? "error" : ""} ${message.type === "deleted" ? "deleted" : ""} ${
                  message.type === "file" ? "file-message" : ""
                }`}
              >
                <div className="message-head">
                  <strong>{message.sender}</strong>
                  <div className="message-meta">
                    <small>{new Date(message.timestamp).toLocaleTimeString()}</small>
                    {message.own && message.type === "chat" && message.messageId && (
                      <button
                        className="link-button message-delete-btn"
                        onClick={() => void deleteOwnMessage(message.messageId)}
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </div>
                {message.type === "file" ? (
                  <div className="file-container">
                    <div className="file-info">
                      <span className="file-icon">📎</span>
                      <div className="file-details">
                        <p className="file-name">{message.fileName}</p>
                        <p className="file-size">{(message.fileSize / 1024).toFixed(1)} KB</p>
                      </div>
                    </div>
                    <button
                      className={`file-download-btn ${downloadingFileIds[message.fileId] ? "loading" : ""}`}
                      onClick={() => void downloadSharedFile(message)}
                      disabled={downloadingFileIds[message.fileId]}
                    >
                      {downloadingFileIds[message.fileId] ? "Downloading..." : "Download"}
                    </button>
                  </div>
                ) : (
                  <p>{message.content}</p>
                )}
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
                {ALL_EMOJIS.map((emoji, index) => (
                  <button
                    key={`${emoji}-${index}`}
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
                void sendMessage()
              }
            }}
          />
          <button onClick={() => void sendMessage()}>Send</button>
        </footer>

        {banner && <p className="error-text">{banner}</p>}
      </main>
    </div>
  )
}

export default App
