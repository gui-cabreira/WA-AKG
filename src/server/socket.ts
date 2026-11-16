import { Server, Socket } from "socket.io";
import { prisma } from "../lib/prisma";
import { canAccessSession } from "../lib/api-auth";
import { logger } from "../lib/logger";

function parseCookies(cookieHeader?: string): Record<string, string> {
    const cookies: Record<string, string> = {};
    if (!cookieHeader) return cookies;

    cookieHeader.split(";").forEach((cookie) => {
        const parts = cookie.split("=");
        if (parts.length >= 2) {
            const key = parts[0].trim();
            const val = parts.slice(1).join("=").trim();
            cookies[key] = decodeURIComponent(val);
        }
    });

    return cookies;
}

export function setupSocket(io: Server) {
    // 🔐 Socket.IO Authentication Middleware
    io.use(async (socket: Socket, next) => {
        try {
            const headers = socket.handshake.headers;
            const cookies = parseCookies(headers.cookie);

            // 1. Try NextAuth JWT session tokens (v4 and v5 cookie names)
            const tokenCookieNames = [
                "authjs.session-token",
                "__Secure-authjs.session-token",
                "next-auth.session-token",
                "__Secure-next-auth.session-token"
            ];

            const secret = process.env.AUTH_SECRET;

            let decodeJwt: typeof import("next-auth/jwt").decode | null = null;
            try {
                const jwtMod = await import("next-auth/jwt");
                decodeJwt = jwtMod.decode;
            } catch (err) {
                logger.debug("Socket", "next-auth/jwt module unavailable:", err);
            }

            if (decodeJwt && secret) {
                // Check auth token in handshake payload or Authorization header
                const authToken = (socket.handshake.auth?.token as string) ||
                                  (headers["authorization"] as string)?.replace(/^Bearer\s+/i, "");

                if (authToken) {
                    for (const salt of ["authjs.session-token", "next-auth.session-token", ""]) {
                        try {
                            const decoded = await decodeJwt({
                                token: authToken,
                                secret,
                                salt
                            });

                            if (decoded && typeof decoded.id === "string" && typeof decoded.exp === "number" && decoded.exp * 1000 > Date.now()) {
                                const currentUser = await prisma.user.findUnique({
                                    where: { id: decoded.id },
                                    select: { id: true, role: true, email: true }
                                });
                                if (currentUser) {
                                    socket.data.user = currentUser;
                                    socket.data.authKind = "jwt";
                                    socket.data.expiresAt = decoded.exp * 1000;
                                    return next();
                                }
                            }
                        } catch {
                            // continue trying salts
                        }
                    }
                }

                // Check cookies
                for (const cookieName of tokenCookieNames) {
                    const chunks = Object.keys(cookies).filter(key => key.startsWith(`${cookieName}.`) && /^\d+$/.test(key.slice(cookieName.length + 1)))
                        .sort((a, b) => Number(a.slice(cookieName.length + 1)) - Number(b.slice(cookieName.length + 1)));
                    const tokenVal = cookies[cookieName] || chunks.map(key => cookies[key]).join("");
                    if (tokenVal) {
                        try {
                            const decoded = await decodeJwt({
                                token: tokenVal,
                                secret,
                                salt: cookieName
                            });

                            if (decoded && typeof decoded.id === "string" && typeof decoded.exp === "number" && decoded.exp * 1000 > Date.now()) {
                                const currentUser = await prisma.user.findUnique({
                                    where: { id: decoded.id },
                                    select: { id: true, role: true, email: true }
                                });
                                if (currentUser) {
                                    socket.data.user = currentUser;
                                    socket.data.authKind = "jwt";
                                    socket.data.expiresAt = decoded.exp * 1000;
                                    return next();
                                }
                            }
                        } catch (e) {
                            logger.debug("Socket", `Failed decoding cookie ${cookieName}:`, e);
                        }
                    }
                }
            }

            // 2. Try API Key from auth payload or x-api-key header
            const apiKey =
                (socket.handshake.auth?.apiKey as string) ||
                (headers["x-api-key"] as string);

            if (apiKey && typeof apiKey === "string") {
                const user = await prisma.user.findUnique({
                    where: { apiKey },
                    select: { id: true, role: true, email: true }
                });

                if (user) {
                    socket.data.authKind = "api-key";
                    socket.data.user = {
                        id: user.id,
                        role: user.role,
                        email: user.email
                    };
                    return next();
                }
            }

            // Reject unauthenticated sockets
            logger.warn("Socket", `Rejected unauthenticated connection attempt from ${socket.id} (IP: ${socket.handshake.address})`);
            return next(new Error("Authentication required"));

        } catch (err) {
            logger.error("Socket", "Error in Socket.IO auth middleware:", err);
            return next(new Error("Internal authentication error"));
        }
    });

    // 📡 Authenticated connection handler
    io.on("connection", (socket: Socket) => {
        const user = socket.data.user;
        logger.info("Socket", `Client connected: ${socket.id} (User: ${user?.id || "unknown"}, Role: ${user?.role || "unknown"})`);

        // Short leases bound already-joined room access after role/key/share revocation.
        // Never keep existing rooms indefinitely while a DB check is hung/unavailable.
        const sessionRooms = new Set<string>();
        const userRooms = new Set<string>();
        let leaseTimer: ReturnType<typeof setTimeout>;
        let refreshInFlight: Promise<boolean> | undefined;
        const revoke = () => { socket.disconnect(true); };
        const renewLease = () => {
            clearTimeout(leaseTimer);
            const remaining = socket.data.authKind === "jwt" ? socket.data.expiresAt - Date.now() : 15000;
            leaseTimer = setTimeout(revoke, Math.max(0, Math.min(15000, remaining)));
            leaseTimer.unref?.();
        };
        const refresh = (): Promise<boolean> => {
            if (refreshInFlight) return refreshInFlight;
            refreshInFlight = (async () => {
                let deadline: ReturnType<typeof setTimeout> | undefined;
                try {
                    const check = async () => {
                        if (socket.data.authKind === "jwt" && socket.data.expiresAt <= Date.now()) return false;
                        const apiKey = socket.handshake.auth?.apiKey || socket.handshake.headers["x-api-key"];
                        const where = socket.data.authKind === "api-key" ? { apiKey: String(apiKey) } : { id: user.id };
                        const current = await prisma.user.findUnique({ where, select: { id: true, role: true, email: true } });
                        if (!current || current.id !== user.id) return false;
                        for (const room of sessionRooms) {
                            if (!await canAccessSession(current.id, current.role, room)) {
                                await socket.leave(room); sessionRooms.delete(room);
                            }
                        }
                        for (const room of userRooms) {
                            if (room !== current.id && current.role !== "SUPERADMIN") {
                                await socket.leave(`user:${room}`); userRooms.delete(room);
                            }
                        }
                        socket.data.user = current;
                        return true;
                    };
                    const allowed = await Promise.race([
                        check(),
                        new Promise<boolean>(resolve => { deadline = setTimeout(() => resolve(false), 5000); deadline.unref?.(); })
                    ]);
                    if (!allowed) { revoke(); return false; }
                    if (socket.connected) renewLease();
                    return allowed && socket.connected;
                } catch (err) {
                    logger.error("Socket", "Access refresh failed", err); revoke(); return false;
                } finally { clearTimeout(deadline); refreshInFlight = undefined; }
            })();
            return refreshInFlight;
        };
        renewLease();
        const refreshTimer = setInterval(() => { void refresh(); }, 5000);
        refreshTimer.unref?.();
        socket.on("disconnect", () => {
            clearTimeout(leaseTimer); clearInterval(refreshTimer);
            sessionRooms.clear(); userRooms.clear();
            logger.info("Socket", `Client disconnected: ${socket.id}`);
        });

        // 🛡️ Authorized Session Room Join
        socket.on("join-session", async (sessionId: string) => {
            try {
                if (!sessionId || typeof sessionId !== "string") {
                    socket.emit("error", { message: "Invalid sessionId" });
                    return;
                }

                if (!socket.data.user) {
                    socket.emit("error", { message: "Unauthorized" });
                    return;
                }

                if (!await refresh()) return;
                const currentUser = socket.data.user;
                if (!currentUser) { socket.emit("error", { message: "Unauthorized" }); return; }
                const canAccess = await canAccessSession(
                    currentUser.id,
                    currentUser.role,
                    sessionId
                );

                if (!canAccess) {
                    logger.warn("Socket", `Forbidden join-session attempt: User ${socket.data.user.id} tried to join session '${sessionId}'`);
                    socket.emit("error", { message: "Forbidden - Cannot access this session" });
                    return;
                }

                if (!socket.connected) return;
                await socket.join(sessionId);
                sessionRooms.add(sessionId);
                logger.debug("Socket", `Socket ${socket.id} (User: ${socket.data.user.id}) joined session room: ${sessionId}`);
            } catch (err) {
                logger.error("Socket", `Error joining session ${sessionId}:`, err);
                socket.emit("error", { message: "Error joining session room" });
            }
        });

        // 🛡️ Authorized User-specific Notification Room Join
        socket.on("join-user-room", async (userId: string) => {
            try {
            if (!userId || typeof userId !== "string") {
                socket.emit("error", { message: "Invalid userId" });
                return;
            }

            if (!socket.data.user) {
                socket.emit("error", { message: "Unauthorized" });
                return;
            }

            if (!await refresh()) return;
            const currentUser = socket.data.user;
            if (!currentUser) { socket.emit("error", { message: "Unauthorized" }); return; }
            // Only allow joining own user room, unless current database role is SUPERADMIN.
            if (currentUser.id !== userId && currentUser.role !== "SUPERADMIN") {
                logger.warn("Socket", `Forbidden join-user-room attempt: User ${socket.data.user.id} tried to join user:${userId}`);
                socket.emit("error", { message: "Forbidden - Cannot access other user room" });
                return;
            }

            if (!socket.connected) return;
            await socket.join(`user:${userId}`);
            userRooms.add(userId);
            logger.debug("Socket", `Socket ${socket.id} joined user room: user:${userId}`);
            } catch (err) {
                logger.error("Socket", "Error checking user room access:", err);
                socket.emit("error", { message: "Error joining user room" });
            }
        });
    });
}
