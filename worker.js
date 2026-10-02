export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "no-store"
        }
      });

    // 🛡️ VPN Checker — checks the visitor's own public IP against 5 sources
    if (url.pathname === "/vpn") {
      const ip = request.headers.get("CF-Connecting-IP");

      if (!ip) return json({ error: true, message: "Unable to detect your IP." }, 400);

      const sources = {};

      const checks = await Promise.allSettled([
        // 1) IP99
        (async () => {
          const r = await fetch(`https://ip99.com/v1/ip/${encodeURIComponent(ip)}`, {
            headers: { "X-API-Key": env.IP99_API_KEY, "Accept": "application/json" }
          });
          const d = await r.json();
          const signals = Array.isArray(d?.risk?.signals) ? d.risk.signals.map(String).map(s => s.toLowerCase()) : [];
          return {
            name: "IP99",
            detected: signals.includes("vpn"),
            status: signals.includes("vpn") ? "VPN detected" : "No VPN signal",
            detail: signals.length ? signals.join(", ") : "No VPN signal"
          };
        })(),

        // 2) HackMyIP
        (async () => {
          const r = await fetch(`https://hackmyip.com/api/lookup?ip=${encodeURIComponent(ip)}`);
          const d = await r.json();
          const p = d?.data?.privacy || {};
          const detected = p.vpn === true || p.is_vpn === true || p.vpn === "true";
          return {
            name: "HackMyIP",
            detected,
            status: detected ? "VPN detected" : "No VPN signal",
            detail: detected ? "VPN/privacy signal" : "No VPN signal"
          };
        })(),

        // 3) ipquery.io
        (async () => {
          const r = await fetch(`https://api.ipquery.io/${encodeURIComponent(ip)}`);
          const d = await r.json();
          const detected = d?.risk?.is_vpn === true;
          return {
            name: "ipquery.io",
            detected,
            status: detected ? "VPN detected" : "No VPN signal",
            detail: detected ? `Risk score: ${d?.risk?.risk_score ?? "N/A"}` : "No VPN signal"
          };
        })(),

        // 4) IPLogs
        (async () => {
          const r = await fetch("https://iplogs.com/v1/check", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({ ip })
          });
          const d = await r.json();
          const verdict = String(d?.verdict || "").toLowerCase();
          const signals = Array.isArray(d?.signals) ? d.signals.map(String).map(s => s.toLowerCase()) : [];
          const detected = d?.vpn_detected === true || d?.is_vpn === true || verdict.includes("vpn") || signals.some(s => s.includes("vpn"));
          return {
            name: "IPLogs",
            detected,
            status: detected ? "VPN detected" : "No VPN signal",
            detail: verdict || (signals.length ? signals.join(", ") : "No VPN signal")
          };
        })(),

        // 5) ProxyCheck.io — VPN-only mode
        (async () => {
          const r = await fetch(`https://proxycheck.io/v3/${encodeURIComponent(ip)}?vpn=2&tag=0`);
          const d = await r.json();
          const entry = d?.[ip] || {};
          const detections = entry?.detections || {};
          const detected = detections.vpn === true || detections.anonymous === true || entry?.type === "VPN";
          return {
            name: "ProxyCheck.io",
            detected,
            status: detected ? "VPN detected" : "No VPN signal",
            detail: detected ? "VPN detection signal" : "No VPN signal"
          };
        })()
      ]);

      checks.forEach((result, i) => {
        const names = ["IP99", "HackMyIP", "ipquery.io", "IPLogs", "ProxyCheck.io"];
        if (result.status === "fulfilled") {
          sources[names[i]] = result.value;
        } else {
          sources[names[i]] = {
            name: names[i],
            detected: null,
            status: "Check unavailable",
            detail: "Source unavailable"
          };
        }
      });

      const results = Object.values(sources);
      const available = results.filter(r => r.detected !== null);
      const positives = available.filter(r => r.detected === true).length;

      let verdict = "NO VPN DETECTED";
      if (positives >= 3) verdict = "VPN DETECTED";
      else if (positives >= 1) verdict = "POSSIBLE VPN";

      return json({
        ip,
        verdict,
        positive: positives,
        checked: available.length,
        total: results.length,
        sources
      });
    }

    if (url.pathname === "/api") {
      const searchedIP = url.searchParams.get("ip");

      // 🔎 Search another IP
      if (searchedIP) {
        if (searchedIP.length > 45 || !/^[0-9a-fA-F:.]+$/.test(searchedIP)) {
          return json({ error: true, message: "Invalid IP address" }, 400);
        }

        try {
          const response = await fetch(
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
              message: data.message || data.error || `IP99 error ${response.status}`
            }, response.status);
          }

          const asnNumber = data.network?.asn;
          let isp = "Unknown";

          if (asnNumber) {
            try {
              const asnResponse = await fetch(`https://api.lookip.io/v1/asn/${asnNumber}`);
              if (asnResponse.ok) {
                const asnData = await asnResponse.json();
                isp = asnData.name || asnData.organization || asnData.orgName || asnData.org || "Unknown";
              }
            } catch {}
          }

          let postal = data.geo?.postal_code || data.geo?.postal || "Unknown";

          if (postal === "Unknown") {
            try {
              const hackResponse = await fetch(`https://hackmyip.com/api/lookup?ip=${encodeURIComponent(searchedIP)}`);
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

      // 🌐 Visitor's own IP — Cloudflare
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
