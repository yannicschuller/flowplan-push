import { BlockList, isIP } from "node:net";

/**
 * Address classification for the SSRF guard. Everything that is not a
 * globally routable unicast address is rejected: private, loopback,
 * link-local, CGNAT, multicast, documentation, benchmarking, reserved, and
 * IPv6 forms that embed such an IPv4 address (IPv4-mapped, IPv4-compatible,
 * NAT64, 6to4) or tunnel to arbitrary IPv4 space (Teredo).
 */

const V4_BLOCKED: Array<[string, number]> = [
  ["0.0.0.0", 8], // "this network"
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // CGNAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local (incl. cloud metadata 169.254.169.254)
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // TEST-NET-1
  ["192.31.196.0", 24], // AS112
  ["192.52.193.0", 24], // AMT
  ["192.88.99.0", 24], // 6to4 relay anycast
  ["192.168.0.0", 16], // private
  ["192.175.48.0", 24], // AS112
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // TEST-NET-2
  ["203.0.113.0", 24], // TEST-NET-3
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved + broadcast
];

const V6_BLOCKED: Array<[string, number]> = [
  ["::", 128], // unspecified
  ["::1", 128], // loopback
  ["::", 96], // IPv4-compatible (deprecated)
  ["::ffff:0:0", 96], // IPv4-mapped (checked via embedded v4 too)
  ["::ffff:0:0:0", 96], // IPv4-translated
  ["64:ff9b:1::", 48], // local-use NAT64
  ["100::", 64], // discard-only
  ["2001::", 23], // IETF protocol assignments (incl. Teredo 2001::/32)
  ["2001:db8::", 32], // documentation
  ["2002::", 16], // 6to4 (embedded v4 checked, but block entirely: rarely legitimate)
  ["3fff::", 20], // documentation
  ["5f00::", 16], // SRv6 SIDs
  ["fc00::", 7], // unique local
  ["fe80::", 10], // link-local
  ["fec0::", 10], // site-local (deprecated)
  ["ff00::", 8], // multicast
];

// Separate lists: a BlockList holding IPv6 rules such as ::ffff:0:0/96 also
// matches plain IPv4 addresses (it maps them), so v4 and v6 are kept apart.
const v4BlockList = new BlockList();
for (const [net, prefix] of V4_BLOCKED) v4BlockList.addSubnet(net, prefix, "ipv4");
const v6BlockList = new BlockList();
for (const [net, prefix] of V6_BLOCKED) v6BlockList.addSubnet(net, prefix, "ipv6");

/** Addresses that are never acceptable, even with ALLOW_PRIVATE_INSTANCES. */
const v4AlwaysBlocked = new BlockList();
v4AlwaysBlocked.addSubnet("0.0.0.0", 8, "ipv4");
v4AlwaysBlocked.addSubnet("224.0.0.0", 4, "ipv4");
v4AlwaysBlocked.addSubnet("240.0.0.0", 4, "ipv4");
const v6AlwaysBlocked = new BlockList();
v6AlwaysBlocked.addAddress("::", "ipv6");
v6AlwaysBlocked.addSubnet("ff00::", 8, "ipv6");

/** Parses an IPv6 address (no zone id) into 16 bytes, or null. */
export function parseIPv6(addr: string): Uint8Array | null {
  if (isIP(addr) !== 6) return null;
  let s = addr;
  const bytes = new Uint8Array(16);
  // Embedded dotted quad at the end.
  let tail: number[] = [];
  const m = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (m?.[1] && m[2]) {
    tail = m[2].split(".").map(Number);
    s = `${m[1]}0:0`;
  }
  const [head, rest] = s.includes("::") ? (s.split("::") as [string, string]) : [s, null];
  const headParts = head ? head.split(":") : [];
  const restParts = rest === null ? [] : rest ? rest.split(":") : [];
  const fill = 8 - headParts.length - restParts.length;
  if (rest === null && headParts.length !== 8) return null;
  if (rest !== null && fill < 1) return null;
  const groups = [...headParts, ...Array(rest === null ? 0 : fill).fill("0"), ...restParts];
  if (groups.length !== 8) return null;
  groups.forEach((g, i) => {
    const v = Number.parseInt(g, 16);
    bytes[i * 2] = (v >> 8) & 0xff;
    bytes[i * 2 + 1] = v & 0xff;
  });
  if (tail.length === 4) bytes.set(tail, 12);
  return bytes;
}

function v4FromBytes(b: Uint8Array, offset: number): string {
  return `${b[offset]}.${b[offset + 1]}.${b[offset + 2]}.${b[offset + 3]}`;
}

/** IPv4 addresses embedded in IPv6 forms that would let traffic reach IPv4 space. */
export function embeddedIPv4(addr: string): string | null {
  const b = parseIPv6(addr);
  if (!b) return null;
  const zero = (from: number, to: number) => b.subarray(from, to).every((x) => x === 0);
  // ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compatible)
  if (zero(0, 10) && ((b[10] === 0xff && b[11] === 0xff) || (b[10] === 0 && b[11] === 0))) {
    return v4FromBytes(b, 12);
  }
  // 64:ff9b::/96 NAT64 well-known prefix
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && zero(4, 12)) {
    return v4FromBytes(b, 12);
  }
  // 2002:aabb:ccdd::/48 6to4
  if (b[0] === 0x20 && b[1] === 0x02) return v4FromBytes(b, 2);
  return null;
}

/** True when the address is a globally routable unicast address. */
export function isPublicAddress(addr: string): boolean {
  if (addr.includes("%")) return false; // zone ids imply link-local scope
  const family = isIP(addr);
  if (family === 4) return !v4BlockList.check(addr, "ipv4");
  if (family === 6) {
    const v4 = embeddedIPv4(addr);
    if (v4 !== null && !isPublicAddress(v4)) return false;
    return !v6BlockList.check(addr, "ipv6");
  }
  return false;
}

/** Address check honouring ALLOW_PRIVATE_INSTANCES. */
export function isAllowedAddress(addr: string, allowPrivate: boolean): boolean {
  if (!allowPrivate) return isPublicAddress(addr);
  const family = isIP(addr);
  if (family === 0 || addr.includes("%")) return false;
  if (family === 4) return !v4AlwaysBlocked.check(addr, "ipv4");
  const v4 = embeddedIPv4(addr);
  if (v4 !== null && v4AlwaysBlocked.check(v4, "ipv4")) return false;
  return !v6AlwaysBlocked.check(addr, "ipv6");
}

/** Key used for per-IP rate limits: IPv4 address, or the /64 prefix for IPv6. */
export function rateLimitKeyForIp(ip: string): string {
  const v4 = embeddedIPv4(ip);
  if (v4 && /^::ffff:/i.test(ip)) return v4;
  const b = parseIPv6(ip);
  if (!b) return ip;
  const groups: string[] = [];
  for (let i = 0; i < 8; i += 2) groups.push((((b[i] ?? 0) << 8) | (b[i + 1] ?? 0)).toString(16));
  return `${groups.join(":")}::/64`;
}
