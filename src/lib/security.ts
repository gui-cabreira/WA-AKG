import dns from "dns";
import net from "net";
import http from "node:http";
import https from "node:https";

/**
 * Checks if an IPv4 or IPv6 address is private, loopback, link-local, or reserved.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
    // Canonicalize IPv6 first, including expanded IPv4-mapped spellings.
    if (net.isIPv6(ip)) {
        ip = new URL(`http://[${ip}]/`).hostname.slice(1, -1).toLowerCase();
        if (ip.startsWith("::ffff:")) {
            const words = ip.slice(7).split(":");
            if (words.length === 2) {
                const hi = parseInt(words[0], 16), lo = parseInt(words[1], 16);
                ip = `${hi >>> 8}.${hi & 255}.${lo >>> 8}.${lo & 255}`;
            }
        }
    }
    // Handle IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
    if (ip.startsWith("::ffff:")) {
        ip = ip.substring(7);
    }

    if (net.isIPv4(ip)) {
        const parts = ip.split(".").map(Number);
        if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
            return true; // Invalid IPv4, treat as unsafe
        }

        const [b0, b1, b2] = parts;

        // 0.0.0.0/8 (Current network / "this" network)
        if (b0 === 0) return true;
        // 10.0.0.0/8 (Private)
        if (b0 === 10) return true;
        // 100.64.0.0/10 (Shared Address Space / CGNAT RFC 6598 - 100.64.0.0 to 100.127.255.255)
        if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;
        // 127.0.0.0/8 (Loopback)
        if (b0 === 127) return true;
        // 169.254.0.0/16 (Link-local / Cloud Metadata: AWS, GCP, Azure, DO, etc.)
        if (b0 === 169 && b1 === 254) return true;
        // 172.16.0.0/12 (Private - 172.16.0.0 to 172.31.255.255)
        if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
        // 192.0.0.0/24 (IETF Protocol Assignments)
        if (b0 === 192 && b1 === 0 && b2 === 0) return true;
        // 192.0.2.0/24 (TEST-NET-1 Documentation)
        if (b0 === 192 && b1 === 0 && b2 === 2) return true;
        // 192.88.99.0/24 (6to4 Relay Anycast)
        if (b0 === 192 && b1 === 88 && b2 === 99) return true;
        // 192.168.0.0/16 (Private)
        if (b0 === 192 && b1 === 168) return true;
        // 198.18.0.0/15 (Network Interconnect Device Benchmark Testing)
        if (b0 === 198 && (b1 === 18 || b1 === 19)) return true;
        // 198.51.100.0/24 (TEST-NET-2 Documentation)
        if (b0 === 198 && b1 === 51 && b2 === 100) return true;
        // 203.0.113.0/24 (TEST-NET-3 Documentation)
        if (b0 === 203 && b1 === 0 && b2 === 113) return true;
        // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
        if (b0 >= 224) return true;
        // Broadcast
        if (ip === "255.255.255.255") return true;

        return false;
    }

    if (net.isIPv6(ip)) {
        const lower = ip.toLowerCase();
        // ::1 (Loopback)
        if (lower === "::1" || lower === "0:0:0:0:0:0:0:1") return true;
        // :: (Unspecified)
        if (lower === "::" || lower === "0:0:0:0:0:0:0:0") return true;
        if (lower.startsWith("ff") || lower.startsWith("fec") || lower.startsWith("fed") || lower.startsWith("fee") || lower.startsWith("fef")) return true;
        // fe80::/10 (Link-local)
        if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) return true;
        // fc00::/7 (Unique local private - fc00::/7 or fd00::/8)
        if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
        // 64:ff9b::/96 (IPv4/IPv6 translation)
        if (lower.startsWith("64:ff9b:")) return true;
        // 2001:db8::/32 (Documentation)
        if (lower.startsWith("2001:db8:") || lower.startsWith("2001:0db8:")) return true;
        // 2002::/16 (6to4)
        if (lower.startsWith("2002:")) return true;

        return false;
    }

    return true; // Unknown address format, treat as unsafe
}

export interface ValidateUrlOptions {
    allowHttp?: boolean;
    allowedHostnames?: string[];
}

/**
 * Validates that a URL is well-formed, uses allowed protocols,
 * and does NOT resolve to internal / private / loopback IP addresses (anti-SSRF).
 */
export async function validateSafeUrl(
    urlStr: string,
    options: ValidateUrlOptions = {}
): Promise<{ valid: boolean; error?: string; url?: URL; resolvedIps?: string[] }> {
    if (!urlStr || typeof urlStr !== "string") {
        return { valid: false, error: "URL must be a non-empty string" };
    }

    let parsed: URL;
    try {
        parsed = new URL(urlStr);
    } catch {
        return { valid: false, error: "Malformed URL" };
    }

    const allowedProtocols = options.allowHttp ? ["https:", "http:"] : ["https:"];
    if (!allowedProtocols.includes(parsed.protocol)) {
        return { valid: false, error: `Protocol '${parsed.protocol}' is not allowed. Only HTTPS is supported.` };
    }

    const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
    if (parsed.username || parsed.password) return { valid: false, error: "URL credentials are forbidden" };
    if (!hostname) {
        return { valid: false, error: "URL missing valid hostname" };
    }

    // Check specific hostnames whitelist if requested
    if (options.allowedHostnames && options.allowedHostnames.length > 0) {
        const matches = options.allowedHostnames.some(allowed => 
            hostname === allowed || hostname.endsWith(`.${allowed}`)
        );
        if (!matches) {
            return { valid: false, error: `Hostname '${hostname}' is not in the allowed domains list` };
        }
    }

    // Direct IP address in hostname
    if (net.isIP(hostname)) {
        if (isPrivateOrReservedIp(hostname)) {
            return { valid: false, error: `Access to private or local IP address (${hostname}) is forbidden` };
        }
        return { valid: true, url: parsed, resolvedIps: [hostname] };
    }

    // Reject localhost explicitly
    if (hostname.toLowerCase() === "localhost" || hostname.toLowerCase().endsWith(".localhost")) {
        return { valid: false, error: "Access to localhost is forbidden" };
    }

    // Resolve DNS and check every returned IP
    try {
        const lookupResults = await dns.promises.lookup(hostname, { all: true });
        if (!lookupResults || lookupResults.length === 0) {
            return { valid: false, error: `Unable to resolve hostname '${hostname}'` };
        }

        const resolvedIps = lookupResults.map(r => r.address);
        for (const res of lookupResults) {
            if (isPrivateOrReservedIp(res.address)) {
                return { valid: false, error: `Hostname resolves to private or internal IP address (${res.address})` };
            }
        }

        return { valid: true, url: parsed, resolvedIps };
    } catch (err: unknown) {
        return { valid: false, error: `DNS lookup failed for '${hostname}': ${err instanceof Error ? err.message : String(err)}` };
    }
}

export interface SafeFetchOptions {
    maxBytes?: number;
    timeoutMs?: number;
    allowHttp?: boolean;
    allowedHostnames?: string[];
}

const DEFAULT_MAX_BYTES = 16 * 1024 * 1024; // 16 MB
const DEFAULT_TIMEOUT_MS = 10000; // 10s

/**
 * Safely fetches a remote file with SSRF protection, size limits, and timeout.
 */
/** Buffered request with DNS pinned to an already validated address and a total deadline. */
export async function safeRequest(urlStr: string, init: {
    method?: string; headers?: Record<string, string>; body?: string;
} = {}, options: SafeFetchOptions = {}): Promise<Response> {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
    return new Promise((resolve, reject) => {
        let request: http.ClientRequest | undefined;
        let settled = false;
        const timer = setTimeout(() => {
            settled = true;
            request?.destroy();
            reject(new Error("Remote request deadline exceeded"));
        }, timeoutMs);
        const fail = (err: Error) => { if (!settled) { settled = true; clearTimeout(timer); reject(err); } };
        void validateSafeUrl(urlStr, options).then(val => {
            if (settled) return;
            if (!val.valid || !val.url || !val.resolvedIps?.length) throw new Error(`SSRF Prevention: ${val.error}`);
            const pinned = val.resolvedIps[0];
            const transport = val.url.protocol === "https:" ? https : http;
            request = transport.request(val.url, {
                method: init.method ?? "GET", headers: init.headers, agent: false,
                lookup: (_hostname, opts, callback) => {
                    const entry = { address: pinned, family: net.isIP(pinned) };
                    if (typeof opts === "object" && opts.all) callback(null, [entry]);
                    else callback(null, pinned, entry.family);
                },
            }, response => {
                const chunks: Buffer[] = [];
                let size = 0;
                response.on("data", (chunk: Buffer) => {
                    size += chunk.length;
                    if (size > maxBytes) {
                        response.destroy(); request?.destroy(); fail(new Error("Remote body exceeds size limit"));
                    } else chunks.push(chunk);
                });
                response.on("error", fail);
                response.on("aborted", () => fail(new Error("Remote body aborted")));
                response.on("end", () => {
                    if (settled) return;
                    try {
                    const headers = new Headers();
                    for (const [key, value] of Object.entries(response.headers)) {
                        if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
                    }
                    const status = response.statusCode ?? 502;
                    if (status < 200 || status > 599) throw new Error(`Unsupported remote HTTP status ${status}`);
                    const result = new Response([204,205,304].includes(status) ? null : new Uint8Array(Buffer.concat(chunks)), { status, headers });
                    settled = true; clearTimeout(timer); resolve(result);
                    } catch (err) { fail(err instanceof Error ? err : new Error("Invalid remote response")); }
                });
            });
            request.on("error", fail);
            request.end(init.body);
        }).catch(fail);
    });
}

export async function safeFetchBuffer(urlStr: string, options: SafeFetchOptions = {}): Promise<{ buffer: Buffer; contentType: string; fileName?: string }> {
    let currentUrl = urlStr;
    const deadline = Date.now() + (options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    for (let redirects = 0; redirects <= 3; redirects++) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw new Error("Remote request deadline exceeded");
        const response = await safeRequest(currentUrl, {}, { ...options, timeoutMs: remaining });
        if (response.status >= 300 && response.status < 400) {
            const location = response.headers.get("location");
            if (!location) throw new Error("Redirect without location");
            currentUrl = new URL(location, currentUrl).toString();
            continue;
        }
        if (!response.ok) throw new Error(`Remote server HTTP ${response.status}`);
        return { buffer: Buffer.from(await response.arrayBuffer()), contentType: response.headers.get("content-type") || "application/octet-stream", fileName: new URL(currentUrl).pathname.split("/").pop() || "media" };
    }
    throw new Error("Too many redirects");
}

/**
 * Inspects an outgoing WhatsApp message payload and safely materializes
 * any media URL (image, video, document, audio, sticker) into an in-memory Buffer.
 * This guarantees that Baileys never receives a raw local file path or SSRF URL.
 */
export async function materializeSafeMediaPayload<T>(messagePayload: T): Promise<T> {
    if (!messagePayload || typeof messagePayload !== "object") return messagePayload;
    const payload: Record<string, unknown> = { ...(messagePayload as Record<string, unknown>) };
    if (payload.text && (payload.image || payload.video || payload.document || payload.audio)) {
        if (!payload.caption) payload.caption = payload.text;
        delete payload.text;
    }
    const limits: Record<string, number> = { sticker: 10, image: 25, video: 100, document: 100, audio: 50, thumbnail: 25, jpegThumbnail: 10 };
    for (const [kind, mb] of Object.entries(limits)) {
        const media = payload[kind];
        if (!media || Buffer.isBuffer(media)) continue;
        const descriptor = typeof media === "object" ? media as Record<string, unknown> : undefined;
        const url = typeof media === "string" ? media : descriptor?.url;
        if (typeof url !== "string" || !url) throw new Error(`Invalid ${kind} media: only buffers or remote URLs are supported`);
        const { buffer, fileName } = await safeFetchBuffer(url, { maxBytes: mb * 1024 * 1024 });
        if (kind === "sticker") {
            const Sticker = (await import("wa-sticker-formatter")).default;
            const sticker = new Sticker(buffer, {
                pack: typeof descriptor?.pack === "string" ? descriptor.pack : "WA-AKG Bot",
                author: typeof descriptor?.author === "string" ? descriptor.author : "WA-AKG",
                type: "full", quality: 50
            });
            payload[kind] = await sticker.toBuffer();
        } else {
            payload[kind] = buffer;
            if (kind === "document" && !payload.fileName && fileName) payload.fileName = fileName;
        }
    }
    if (payload.header && typeof payload.header === "object" && !Buffer.isBuffer(payload.header)) {
        payload.header = await materializeSafeMediaPayload(payload.header);
    }
    return payload as T;
}
