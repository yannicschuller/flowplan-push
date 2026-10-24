import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";
import { generateInstanceKey, wellKnownDocument } from "../examples/instance.ts";
import { InstanceKeyResolver, parseWellKnown } from "../src/instance/keys.ts";
import {
  embeddedIPv4,
  isAllowedAddress,
  isPublicAddress,
  parseIPv6,
  rateLimitKeyForIp,
} from "../src/net/ip.ts";
import { canonicalOrigin } from "../src/net/origin.ts";
import { type Resolver, SafeFetchError, safeFetch } from "../src/net/safeFetch.ts";

describe("address policy", () => {
  const blocked = [
    "127.0.0.1",
    "127.1.2.3",
    "10.0.0.1",
    "172.16.5.4",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254", // cloud metadata
    "100.64.0.1", // CGNAT
    "100.127.255.254",
    "0.0.0.0",
    "224.0.0.1", // multicast
    "239.255.255.250",
    "255.255.255.255",
    "192.0.2.1",
    "198.18.0.1",
    "::1",
    "::",
    "fe80::1",
    "fc00::1",
    "fd12:3456::1",
    "ff02::1",
    "::ffff:127.0.0.1", // IPv4-mapped loopback
    "::ffff:7f00:1", // same, hex form
    "::ffff:10.0.0.1",
    "::ffff:169.254.169.254",
    "::ffff:8.8.8.8", // mapped addresses are never used for outbound connections
    "::127.0.0.1", // IPv4-compatible
    "64:ff9b::7f00:1", // NAT64 → 127.0.0.1
    "64:ff9b::a00:1", // NAT64 → 10.0.0.1
    "2002:7f00:1::1", // 6to4 → 127.0.0.1
    "2001:0::1", // Teredo
    "2001:db8::1",
    "fe80::1%eth0",
    "not-an-ip",
  ];
  for (const ip of blocked) {
    it(`blocks ${ip}`, () => assert.equal(isPublicAddress(ip), false));
  }
  for (const ip of [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "2606:4700:4700::1111",
    "2a00:1450:4001:82b::200e",
    "64:ff9b::808:808",
  ]) {
    it(`allows ${ip}`, () => assert.equal(isPublicAddress(ip), true));
  }

  it("ALLOW_PRIVATE_INSTANCES allows private but never unspecified/multicast", () => {
    assert.ok(isAllowedAddress("127.0.0.1", true));
    assert.ok(isAllowedAddress("10.1.2.3", true));
    assert.ok(!isAllowedAddress("0.0.0.0", true));
    assert.ok(!isAllowedAddress("224.0.0.1", true));
    assert.ok(!isAllowedAddress("::", true));
  });

  it("parses IPv6 and extracts embedded IPv4", () => {
    assert.deepEqual([...(parseIPv6("::1") ?? [])], [...new Uint8Array(15), 1]);
    assert.equal(embeddedIPv4("::ffff:7f00:1"), "127.0.0.1");
    assert.equal(embeddedIPv4("::ffff:192.168.0.1"), "192.168.0.1");
    assert.equal(embeddedIPv4("2606:4700::1"), null);
  });

  it("keys IPv6 rate limits by /64", () => {
    assert.equal(
      rateLimitKeyForIp("2001:db8:1:2:3:4:5:6"),
      rateLimitKeyForIp("2001:db8:1:2:ffff::1"),
    );
    assert.notEqual(rateLimitKeyForIp("2001:db8:1:2::1"), rateLimitKeyForIp("2001:db8:1:3::1"));
    assert.equal(rateLimitKeyForIp("::ffff:1.2.3.4"), "1.2.3.4");
    assert.equal(rateLimitKeyForIp("1.2.3.4"), "1.2.3.4");
  });
});

describe("instance origins", () => {
  it("canonicalises valid origins", () => {
    assert.equal(canonicalOrigin("https://app.flowplan.org", false), "https://app.flowplan.org");
    assert.equal(canonicalOrigin("https://App.Flowplan.org/", false), "https://app.flowplan.org");
    assert.equal(
      canonicalOrigin("https://app.flowplan.org:443", false),
      "https://app.flowplan.org",
    );
    assert.equal(
      canonicalOrigin("https://flowplan.example.com:8443", false),
      "https://flowplan.example.com:8443",
    );
    assert.equal(canonicalOrigin("https://bücher.example", false), "https://xn--bcher-kva.example");
  });
  const bad = [
    "http://app.flowplan.org",
    "https://app.flowplan.org/path",
    "https://app.flowplan.org?x=1",
    "https://app.flowplan.org#x",
    "https://user:pw@app.flowplan.org",
    "https://localhost",
    "https://intranet",
    "https://127.0.0.1",
    "https://[::1]",
    "https://10.0.0.1",
    "https://169.254.169.254",
    "https://[::ffff:127.0.0.1]",
    "https://printer.local",
    "ftp://app.flowplan.org",
    "javascript:alert(1)",
    "https:app.flowplan.org",
    " https://app.flowplan.org",
    "https://app.flowplan.org\n",
    `https://${"a".repeat(260)}.org`,
  ];
  for (const o of bad) {
    it(`rejects ${JSON.stringify(o).slice(0, 60)}`, () =>
      assert.equal(canonicalOrigin(o, false), null));
  }
  it("allows http://localhost only with ALLOW_PRIVATE_INSTANCES", () => {
    assert.equal(canonicalOrigin("http://localhost:3000", true), "http://localhost:3000");
    assert.equal(canonicalOrigin("http://localhost:3000", false), null);
    assert.equal(canonicalOrigin("http://10.0.0.5", true), null, "http only for localhost");
    assert.equal(canonicalOrigin("https://10.0.0.5", true), "https://10.0.0.5");
  });
});

describe("safeFetch", () => {
  let server: http.Server;
  let port: number;
  let hits: string[] = [];
  before(async () => {
    server = http.createServer((req, res) => {
      hits.push(req.url ?? "");
      if (req.url === "/redirect-same") {
        res.writeHead(302, { location: "/.well-known/flowplan-push" }).end();
      } else if (req.url === "/redirect-other") {
        res.writeHead(302, { location: "http://127.0.0.2:1/.well-known/flowplan-push" }).end();
      } else if (req.url === "/redirect-loop") {
        res.writeHead(302, { location: "/redirect-loop" }).end();
      } else if (req.url === "/big") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ x: "a".repeat(20_000) }));
      } else if (req.url === "/slow") {
        res.writeHead(200, { "content-type": "application/json" });
        res.write("{");
        setTimeout(() => res.end("}"), 2000).unref();
      } else {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(wellKnownDocument([generateInstanceKey("k1")])));
      }
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as AddressInfo).port;
  });
  after(async () => {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
  });

  const resolverTo =
    (...addresses: string[]): Resolver =>
    async () =>
      addresses.map((address) => ({ address, family: address.includes(":") ? 6 : 4 }));

  const code = async (p: Promise<unknown>) => {
    try {
      await p;
      return "ok";
    } catch (e) {
      return e instanceof SafeFetchError ? e.code : `other:${(e as Error).message}`;
    }
  };

  it("rejects plain http on a public relay", async () => {
    assert.equal(
      await code(safeFetch("http://example.com/x", { allowPrivate: false })),
      "scheme_not_allowed",
    );
    assert.equal(
      await code(safeFetch(`http://localhost:${port}/`, { allowPrivate: false })),
      "scheme_not_allowed",
    );
  });

  it("rejects host names resolving to private, loopback or mapped addresses", async () => {
    for (const addrs of [
      ["127.0.0.1"],
      ["10.0.0.1"],
      ["169.254.169.254"],
      ["::ffff:127.0.0.1"],
      ["fd00::1"],
      ["93.184.216.34", "127.0.0.1"],
    ]) {
      assert.equal(
        await code(
          safeFetch("https://evil.example/.well-known/flowplan-push", {
            allowPrivate: false,
            resolver: resolverTo(...addrs),
          }),
        ),
        "address_not_allowed",
        addrs.join(","),
      );
    }
  });

  it("rejects IP literals in private ranges", async () => {
    assert.equal(
      await code(safeFetch("https://127.0.0.1/", { allowPrivate: false })),
      "address_not_allowed",
    );
    assert.equal(
      await code(safeFetch("https://[::ffff:7f00:1]/", { allowPrivate: false })),
      "address_not_allowed",
    );
  });

  it("pins the connection to the checked address (no second DNS lookup)", async () => {
    let lookups = 0;
    const resolver: Resolver = async () => {
      lookups++;
      return [{ address: "127.0.0.1", family: 4 }];
    };
    hits = [];
    const res = await safeFetch(`http://localhost:${port}/.well-known/flowplan-push`, {
      allowPrivate: true,
      resolver,
    });
    assert.equal(res.status, 200);
    assert.equal(res.address, "127.0.0.1");
    assert.equal(lookups, 1);
    assert.deepEqual(hits, ["/.well-known/flowplan-push"]);
    assert.equal(parseWellKnown(res.body).length, 1);
  });

  it("follows same-origin redirects only", async () => {
    const resolver = resolverTo("127.0.0.1");
    const ok = await safeFetch(`http://localhost:${port}/redirect-same`, {
      allowPrivate: true,
      resolver,
    });
    assert.equal(ok.status, 200);
    assert.equal(
      await code(
        safeFetch(`http://localhost:${port}/redirect-other`, { allowPrivate: true, resolver }),
      ),
      "cross_origin_redirect",
    );
    assert.equal(
      await code(
        safeFetch(`http://localhost:${port}/redirect-loop`, { allowPrivate: true, resolver }),
      ),
      "too_many_redirects",
    );
  });

  it("limits the response size and the total time", async () => {
    const resolver = resolverTo("127.0.0.1");
    assert.equal(
      await code(safeFetch(`http://localhost:${port}/big`, { allowPrivate: true, resolver })),
      "too_large",
    );
    assert.equal(
      await code(
        safeFetch(`http://localhost:${port}/slow`, {
          allowPrivate: true,
          resolver,
          timeoutMs: 200,
        }),
      ),
      "timeout",
    );
    const slowDns: Resolver = () =>
      new Promise((r) => setTimeout(() => r([{ address: "127.0.0.1", family: 4 }]), 1000).unref());
    assert.equal(
      await code(
        safeFetch(`http://localhost:${port}/`, {
          allowPrivate: true,
          resolver: slowDns,
          timeoutMs: 100,
        }),
      ),
      "timeout",
    );
  });

  it("InstanceKeyResolver caches, re-fetches unknown kids at most once per minute, and never uses stale keys", async () => {
    let t = 1_000_000;
    let fetchCount = 0;
    let doc = [generateInstanceKey("k1")];
    const resolver = new InstanceKeyResolver({
      now: () => t,
      fetchDocument: async () => {
        fetchCount++;
        const { createPublicKey } = await import("node:crypto");
        return doc.map((k) => ({ id: k.kid, key: createPublicKey(k.privateKey) }));
      },
    });
    assert.ok((await resolver.getKey("https://a.example", "k1")).ok);
    assert.ok((await resolver.getKey("https://a.example", "k1")).ok);
    assert.equal(fetchCount, 1);
    // unknown kid within a minute → no re-fetch
    assert.deepEqual(await resolver.getKey("https://a.example", "k2"), {
      ok: false,
      reason: "unknown_key",
    });
    assert.equal(fetchCount, 1);
    // after a minute → re-fetch finds the rotated key
    doc = [doc[0] as (typeof doc)[number], generateInstanceKey("k2")];
    t += 61_000;
    assert.ok((await resolver.getKey("https://a.example", "k2")).ok);
    assert.equal(fetchCount, 2);
    // after an hour the cache expires; a failing fetch means no key (no stale use)
    t += 3_600_000;
    doc = [];
    const r = await resolver.getKey("https://a.example", "k1");
    assert.equal(r.ok, false);
    assert.equal(fetchCount, 3);
  });
});
