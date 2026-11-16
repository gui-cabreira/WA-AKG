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
    } catch (err: any) {
        return { valid: false, error: `DNS lookup failed for '${hostname}': ${err.message}` };
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
                    settled = true; clearTimeout(timer);
                    const headers = new Headers();
                    for (const [key, value] of Object.entries(response.headers)) {
                        if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
                    }
                    const status = response.statusCode ?? 502;
                    resolve(new Response([204,205,304].includes(status) ? null : new Uint8Array(Buffer.concat(chunks)), { status, headers }));
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
export async function materializeSafeMediaPayload(messagePayload: any): Promise<any> {
    if (!messagePayload || typeof messagePayload !== "object") {
        return messagePayload;
    }

    const payload = { ...messagePayload };

    // Normalize "text" to "caption" if a media message is sent with "text"
    if (payload.text && (payload.image || payload.video || payload.document || payload.audio)) {
        if (!payload.caption) {
            payload.caption = payload.text;
        }
        delete payload.text;
    }

    // Sticker
    if (payload.sticker) {
        let stickerUrl: string | null = null;
        if (typeof payload.sticker === "string") {
            stickerUrl = payload.sticker;
        } else if (typeof payload.sticker === "object" && payload.sticker.url) {
            stickerUrl = payload.sticker.url;
        }

        if (stickerUrl) {
            try {
                const { buffer } = await safeFetchBuffer(stickerUrl, { maxBytes: 10 * 1024 * 1024 });
                const Sticker = (await import("wa-sticker-formatter")).default;
                const sticker = new Sticker(buffer, {
                    pack: (typeof payload.sticker === "object" && payload.sticker.pack) || "WA-AKG Bot",
                    author: (typeof payload.sticker === "object" && payload.sticker.author) || "WA-AKG",
                    type: "full",
                    quality: 50
                });
                payload.sticker = await sticker.toBuffer();
            } catch (e: any) {
                throw new Error(`Failed to process sticker media: ${e.message}`);
            }
        } else if (typeof payload.sticker === "object" && !Buffer.isBuffer(payload.sticker)) {
            if ((payload.sticker as any).stream || (payload.sticker as any).path || (payload.sticker as any).filePath) {
                throw new Error("Stream uploads are not permitted in message payload");
            }
        }
    }

    // Image
    if (payload.image) {
        let imageUrl: string | null = null;
        if (typeof payload.image === "string") {
            imageUrl = payload.image;
        } else if (typeof payload.image === "object" && payload.image.url) {
            imageUrl = payload.image.url;
        }

        if (imageUrl) {
            try {
                const { buffer } = await safeFetchBuffer(imageUrl, { maxBytes: 25 * 1024 * 1024 });
                payload.image = buffer;
            } catch (e: any) {
                throw new Error(`Failed to process image media: ${e.message}`);
            }
        } else if (typeof payload.image === "object" && !Buffer.isBuffer(payload.image)) {
            if ((payload.image as any).stream || (payload.image as any).path || (payload.image as any).filePath) {
                throw new Error("Stream uploads are not permitted in message payload");
            }
        }
    }

    // Video
    if (payload.video) {
        let videoUrl: string | null = null;
        if (typeof payload.video === "string") {
            videoUrl = payload.video;
        } else if (typeof payload.video === "object" && payload.video.url) {
            videoUrl = payload.video.url;
        }

        if (videoUrl) {
            try {
                const { buffer } = await safeFetchBuffer(videoUrl, { maxBytes: 100 * 1024 * 1024 });
                payload.video = buffer;
            } catch (e: any) {
                throw new Error(`Failed to process video media: ${e.message}`);
            }
        } else if (typeof payload.video === "object" && !Buffer.isBuffer(payload.video)) {
            if ((payload.video as any).stream || (payload.video as any).path || (payload.video as any).filePath) {
                throw new Error("Stream uploads are not permitted in message payload");
            }
        }
    }

    // Document
    if (payload.document) {
        let docUrl: string | null = null;
        if (typeof payload.document === "string") {
            docUrl = payload.document;
        } else if (typeof payload.document === "object" && payload.document.url) {
            docUrl = payload.document.url;
        }

        if (docUrl) {
            try {
                const { buffer, fileName } = await safeFetchBuffer(docUrl, { maxBytes: 100 * 1024 * 1024 });
                payload.document = buffer;
                if (!payload.fileName && fileName) {
                    payload.fileName = fileName;
                }
            } catch (e: any) {
                throw new Error(`Failed to process document media: ${e.message}`);
            }
        } else if (typeof payload.document === "object" && !Buffer.isBuffer(payload.document)) {
            if ((payload.document as any).stream || (payload.document as any).path || (payload.document as any).filePath) {
                throw new Error("Stream uploads are not permitted in message payload");
            }
        }
    }

    // Audio
    if (payload.audio) {
        let audioUrl: string | null = null;
        if (typeof payload.audio === "string") {
            audioUrl = payload.audio;
        } else if (typeof payload.audio === "object" && payload.audio.url) {
            audioUrl = payload.audio.url;
        }

        if (audioUrl) {
            try {
                const { buffer } = await safeFetchBuffer(audioUrl, { maxBytes: 50 * 1024 * 1024 });
                payload.audio = buffer;
            } catch (e: any) {
                throw new Error(`Failed to process audio media: ${e.message}`);
            }
        } else if (typeof payload.audio === "object" && !Buffer.isBuffer(payload.audio)) {
            if ((payload.audio as any).stream || (payload.audio as any).path || (payload.audio as any).filePath) {
                throw new Error("Stream uploads are not permitted in message payload");
            }
        }
    }

    // Thumbnail
    if (payload.thumbnail) {
        let thumbUrl: string | null = null;
        if (typeof payload.thumbnail === "string") {
            thumbUrl = payload.thumbnail;
        } else if (typeof payload.thumbnail === "object" && payload.thumbnail.url) {
            thumbUrl = payload.thumbnail.url;
        }

        if (thumbUrl) {
            try {
                const { buffer } = await safeFetchBuffer(thumbUrl, { maxBytes: 25 * 1024 * 1024 });
                payload.thumbnail = buffer;
            } catch (e: any) {
                throw new Error(`Failed to process thumbnail media: ${e.message}`);
            }
        } else if (typeof payload.thumbnail === "object" && !Buffer.isBuffer(payload.thumbnail)) {
            if ((payload.thumbnail as any).stream || (payload.thumbnail as any).path || (payload.thumbnail as any).filePath) {
                throw new Error("Stream uploads are not permitted in message payload");
            }
        }
    }

    // jpegThumbnail
    if (payload.jpegThumbnail) {
        let thumbUrl: string | null = null;
        if (typeof payload.jpegThumbnail === "string") {
            thumbUrl = payload.jpegThumbnail;
        } else if (typeof payload.jpegThumbnail === "object" && payload.jpegThumbnail.url) {
            thumbUrl = payload.jpegThumbnail.url;
        }

        if (thumbUrl) {
            try {
                const { buffer } = await safeFetchBuffer(thumbUrl, { maxBytes: 10 * 1024 * 1024 });
                payload.jpegThumbnail = buffer;
            } catch (e: any) {
                throw new Error(`Failed to process jpegThumbnail media: ${e.message}`);
            }
        } else if (typeof payload.jpegThumbnail === "object" && !Buffer.isBuffer(payload.jpegThumbnail)) {
            if ((payload.jpegThumbnail as any).stream || (payload.jpegThumbnail as any).path || (payload.jpegThumbnail as any).filePath) {
                throw new Error("Stream uploads are not permitted in message payload");
            }
        }
    }

    // Header media (for interactive messages)
    if (payload.header && typeof payload.header === "object" && !Buffer.isBuffer(payload.header)) {
        payload.header = await materializeSafeMediaPayload(payload.header);
    }

    return payload;
}

