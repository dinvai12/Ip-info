export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const json = (data, status = 200) => new Response(JSON.stringify(data), {
      status,
      headers: {
        "Content-Type": "application/json; charset=UTF-8",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-store"
      }
    });

    const validIP = ip =>
      typeof ip === "string" &&
      ip.length <= 45 &&
      /^[0-9a-fA-F:.]+$/.test(ip);

    const safeFetch = async (input, init = {}, timeout = 5000) => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      try {
        return await fetch(input, { ...init, signal: controller.signal });
      } finally {
        clearTimeout(timer);
      }
    };

    if (url.pathname === "/api") {
      const searchedIP = url.searchParams.get("ip");
      const vpnCheck = url.searchParams.get("vpn") === "1";

      const clientIP =
        searchedIP ||
        request.headers.get("CF-Connecting-IP") ||
        "Unknown";

      if (!validIP(clientIP)) {
        return json({ error: true, message: "Invalid IP address" }, 400);
      }

      // 🛡️ 10-source VPN checker.
      // Only explicit VPN signals count. Hosting/datacenter/proxy alone
      // is not counted as VPN.
      if (vpnCheck) {
        const sources = {
          iplogs: { name: "IPLogs", detected: null, status: "Unavailable" },
          ip99: { name: "IP99", detected: null, status: "Unavailable" },
          hackmyip: { name: "HackMyIP", detected: null, status: "Unavailable" },
          proxycheck: { name: "ProxyCheck.io", detected: null, status: "Unavailable" },
          ipqs: { name: "IPQualityScore", detected: null, status: "Unavailable" },
          vpnapi: { name: "VPNAPI.io", detected: null, status: "Unavailable" },
          scamalytics: { name: "Scamalytics", detected: null, status: "Unavailable" },
          ipinfo: { name: "IPinfo Privacy", detected: null, status: "Unavailable" },
          ip2proxy: { name: "IP2Location/IP2Proxy", detected: null, status: "Unavailable" },
          getipintel: { name: "GetIPIntel", detected: null, status: "Unavailable" }
        };

        const signals = [];

        const setSource = (key, yes, detail = "") => {
          sources[key].detected = !!yes;
          sources[key].status = yes ? "VPN" : "No VPN";
          if (yes) signals.push(`${sources[key].name}: VPN${detail ? " (" + detail + ")" : ""}`);
        };

        const jobs = [];

        // 1) IPLogs — free/no key.
        jobs.push((async () => {
          try {
            const r = await safeFetch("https://iplogs.com/v1/check", {
              method: "POST",
              headers: { "Content-Type": "application/json", "Accept": "application/json" },
              body: JSON.stringify({ ip: clientIP })
            });
            if (!r.ok) return;
            const d = await r.json();
            const yes = d?.is_vpn === true;
            setSource("iplogs", yes, d?.verdict || "");
          } catch {}
        })());

        // 2) IP99 — existing secret is optional.
        jobs.push((async () => {
          try {
            const headers = { "Accept": "application/json" };
            if (env.IP99_API_KEY) headers["X-API-Key"] = env.IP99_API_KEY;
            const r = await safeFetch(`https://ip99.com/v1/ip/${encodeURIComponent(clientIP)}`, { headers });
            if (!r.ok) return;
            const d = await r.json();
            const rs = Array.isArray(d?.risk?.signals) ? d.risk.signals : [];
            setSource("ip99", rs.includes("vpn"));
          } catch {}
        })());

        // 3) HackMyIP — explicit VPN field only.
        jobs.push((async () => {
          try {
            const r = await safeFetch(`https://hackmyip.com/api/lookup?ip=${encodeURIComponent(clientIP)}`);
            if (!r.ok) return;
            const d = await r.json();
            const p = d?.data?.privacy || {};
            if (typeof p.is_vpn === "boolean") setSource("hackmyip", p.is_vpn);
          } catch {}
        })());

        // 4) ProxyCheck.io — v3. If a key is not configured, it uses its
        // public/free allowance. We inspect only the VPN detection flag.
        jobs.push((async () => {
          try {
            const key = env.PROXYCHECK_API_KEY;
            const qs = key
              ? `?vpn=2&key=${encodeURIComponent(key)}`
              : `?vpn=2`;
            const r = await safeFetch(`https://proxycheck.io/v2/${encodeURIComponent(clientIP)}${qs}`);
            if (!r.ok) return;
            const d = await r.json();
            const row = d?.[clientIP];
            const type = String(row?.type || "").toUpperCase();
            if (type === "VPN") setSource("proxycheck", true);
            else if (row && (row?.type === "Clean" || row?.type === "Residential")) setSource("proxycheck", false);
          } catch {}
        })());

        // 5) IPQualityScore — API key required.
        jobs.push((async () => {
          if (!env.IPQS_API_KEY) return;
          try {
            const r = await safeFetch(
              `https://ipqualityscore.com/api/json/ip/${encodeURIComponent(env.IPQS_API_KEY)}/${encodeURIComponent(clientIP)}`
            );
            if (!r.ok) return;
            const d = await r.json();
            if (typeof d?.vpn === "boolean") setSource("ipqs", d.vpn);
          } catch {}
        })());

        // 6) VPNAPI.io — API key required.
        jobs.push((async () => {
          if (!env.VPNAPI_KEY) return;
          try {
            const r = await safeFetch(
              `https://vpnapi.io/api/${encodeURIComponent(clientIP)}?key=${encodeURIComponent(env.VPNAPI_KEY)}`
            );
            if (!r.ok) return;
            const d = await r.json();
            if (typeof d?.security?.vpn === "boolean") setSource("vpnapi", d.security.vpn);
          } catch {}
        })());

        // 7) Scamalytics — username + API key required.
        // The account is tied to the node selected at signup. If no
        // SCAMALYTICS_API_BASE secret is set, try both documented nodes and
        // use the first successful response.
        jobs.push((async () => {
          if (!env.SCAMALYTICS_USERNAME || !env.SCAMALYTICS_API_KEY) return;

          const configured = env.SCAMALYTICS_API_BASE
            ? [env.SCAMALYTICS_API_BASE]
            : [
                "https://api12.scamalytics.com/v3/",
                "https://api11.scamalytics.com/v3/"
              ];

          for (const base of configured) {
            try {
              const endpoint =
                `${base.replace(/\/?$/, "/")}` +
                `${encodeURIComponent(env.SCAMALYTICS_USERNAME)}` +
                `?key=${encodeURIComponent(env.SCAMALYTICS_API_KEY)}` +
                `&ip=${encodeURIComponent(clientIP)}`;

              const r = await safeFetch(endpoint, {}, 6000);
              if (!r.ok) continue;

              const d = await r.json();
              const s = d?.scamalytics;

              // HTTP 200 can still contain an application-level error.
              if (s?.status !== "ok") continue;

              const yes = s?.scamalytics_proxy?.is_vpn === true;
              if (typeof yes === "boolean") {
                setSource("scamalytics", yes);
                break;
              }
            } catch {}
          }
        })());

        // 8) IPinfo Privacy — token required and privacy detection access required.
        jobs.push((async () => {
          if (!env.IPINFO_TOKEN) return;
          try {
            const r = await safeFetch(
              `https://ipinfo.io/${encodeURIComponent(clientIP)}/privacy?token=${encodeURIComponent(env.IPINFO_TOKEN)}`
            );
            if (!r.ok) return;
            const d = await r.json();
            if (typeof d?.vpn === "boolean") setSource("ipinfo", d.vpn);
          } catch {}
        })());

        // 9) IP2Proxy/IP2Location — key required. IP2Proxy web-service response
        // commonly exposes proxyType; only explicit VPN values count.
        jobs.push((async () => {
          if (!env.IP2PROXY_API_KEY) return;
          try {
            const r = await safeFetch(
              `https://api.ip2proxy.com/?key=${encodeURIComponent(env.IP2PROXY_API_KEY)}&ip=${encodeURIComponent(clientIP)}&format=json`
            );
            if (!r.ok) return;
            const d = await r.json();
            const t = String(d?.proxyType || d?.proxy_type || "").toUpperCase();
            if (t) setSource("ip2proxy", ["VPN", "VPN-ANONYMOUS", "VPN-RESIDENTIAL"].includes(t));
          } catch {}
        })());

        // 10) GetIPIntel — contact/email required. Its response is a
        // probability, not a boolean, so >= 0.99 is treated as a strong signal.
        jobs.push((async () => {
          if (!env.GETIPINTEL_CONTACT) return;
          try {
            const r = await safeFetch(
              `https://check.getipintel.net/check.php?ip=${encodeURIComponent(clientIP)}&contact=${encodeURIComponent(env.GETIPINTEL_CONTACT)}&flags=m`
            );
            if (!r.ok) return;
            const raw = (await r.text()).trim();
            const n = Number(raw);
            if (Number.isFinite(n)) setSource("getipintel", n >= 0.99, `score ${n.toFixed(3)}`);
          } catch {}
        })());

        await Promise.allSettled(jobs);

        const checked = Object.values(sources).filter(s => s.detected !== null);
        const positive = checked.filter(s => s.detected === true).length;

        let status = "clean";
        if (positive >= 2) status = "detected";
        else if (positive === 1) status = "possible";

        return json({
          ip: clientIP,
          status,
          detected_sources: positive,
          checked_sources: checked.length,
          total_sources: 10,
          sources,
          signals
        });
      }

      // 🔎 Search another IP — preserve the existing IP-info behavior.
      if (searchedIP) {
        try {
          const response = await safeFetch(
            `https://ip99.com/v1/ip/${encodeURIComponent(searchedIP)}`,
            {
              headers: {
                "X-API-Key": env.IP99_API_KEY,
                "Accept": "application/json"
              }
            }
          );

          const data = await response.json();

          if (!response.ok) {
            return json({
              error: true,
              message: data?.error?.message || data?.message || `IP99 error ${response.status}`
            }, response.status);
          }

          const asnNumber = data.network?.asn;
          let isp = "Unknown";

          if (asnNumber) {
            try {
              const asnResponse = await safeFetch(
                `https://api.lookip.io/v1/asn/${asnNumber}`
              );
              if (asnResponse.ok) {
                const asnData = await asnResponse.json();
                isp = asnData.name || asnData.organization || asnData.orgName || asnData.org || "Unknown";
              }
            } catch {}
          }

          let postal = data.geo?.postal_code || data.geo?.postal || "Unknown";

          if (postal === "Unknown") {
            try {
              const hackResponse = await safeFetch(
                `https://hackmyip.com/api/lookup?ip=${encodeURIComponent(searchedIP)}`
              );
              if (hackResponse.ok) {
                const hackResult = await hackResponse.json();
                postal = hackResult?.data?.location?.postal_code || "Unknown";
                if (isp === "Unknown") {
                  isp = hackResult?.data?.network?.isp || hackResult?.data?.network?.org || "Unknown";
                }
              }
            } catch {}
          }

          return json({
            ip: data.ip || searchedIP,
            country: data.geo?.country || "Unknown",
            city: data.geo?.city || "Unknown",
            region: data.geo?.region || "Unknown",
            postal,
            timezone: data.geo?.tz || data.geo?.timezone || "Unknown",
            latitude: data.geo?.lat ?? data.geo?.latitude ?? "Unknown",
            longitude: data.geo?.lon ?? data.geo?.longitude ?? "Unknown",
            asn: asnNumber != null ? `AS${asnNumber}` : "Unknown",
            isp,
            colo: "N/A"
          });
        } catch {
          return json({ error: true, message: "IP lookup service unavailable" }, 502);
        }
      }

      // 🌐 Visitor's own IP — Cloudflare.
      const cf = request.cf || {};
      return json({
        ip: request.headers.get("CF-Connecting-IP") || "Unknown",
        country: cf.country || "Unknown",
        city: cf.city || "Unknown",
        region: cf.region || "Unknown",
        postal: cf.postalCode || "Unknown",
        timezone: cf.timezone || "Unknown",
        latitude: cf.latitude || "Unknown",
        longitude: cf.longitude || "Unknown",
        asn: cf.asn ? `AS${cf.asn}` : "Unknown",
        isp: cf.asOrganization || "Unknown",
        colo: cf.colo || "Unknown"
      });
    }

    return env.ASSETS.fetch(request);
  }
};
