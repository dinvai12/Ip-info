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

    const safeFetch = async (input, init = {}, timeout = 5000) => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      try {
        return await fetch(input, { ...init, signal: controller.signal });
      } finally {
        clearTimeout(timer);
      }
    };

    // Retry only network/timeouts and 5xx responses. Do not retry 4xx responses.
    const fetchWithRetry = async (input, init = {}, timeout = 5000, retries = 1) => {
      let lastError;

      for (let attempt = 0; attempt <= retries; attempt++) {
        try {
          const response = await safeFetch(input, init, timeout);

          if (response.ok || (response.status >= 400 && response.status < 500)) {
            return response;
          }

          lastError = new Error(`HTTP ${response.status}`);
        } catch (error) {
          lastError = error;
        }

        if (attempt < retries) {
          await new Promise(resolve => setTimeout(resolve, 350));
        }
      }

      throw lastError || new Error("Request failed");
    };

    if (url.pathname === "/api") {
      const searchedIP = url.searchParams.get("ip");
      const vpnCheck = url.searchParams.get("vpn") === "1";
      const torCheck = url.searchParams.get("tor") === "1";

      const clientIP =
        searchedIP ||
        request.headers.get("CF-Connecting-IP") ||
        "Unknown";

      if (
        clientIP === "Unknown" ||
        clientIP.length > 45 ||
        !/^[0-9a-fA-F:.]+$/.test(clientIP)
      ) {
        return json({ error: true, message: "Invalid IP address" }, 400);
      }

      // Dedicated Tor exit-node check.
      // Uses the Tor Project's current bulk exit list. This is intentionally
      // separate from the VPN checker so VPN/Proxy signals are not mislabeled as Tor.
      if (torCheck) {
        try {
          const r = await safeFetch(
            "https://check.torproject.org/torbulkexitlist",
            {
              headers: {
                "Accept": "text/plain",
                "Cache-Control": "no-cache"
              }
            },
            7000
          );

          if (!r.ok) {
            return json({
              error: true,
              message: `Tor Project list unavailable (${r.status})`
            }, 502);
          }

          const body = await r.text();
          const exits = new Set(
            body
              .split(/\s+/)
              .map(s => s.trim())
              .filter(s => /^[0-9a-fA-F:.]+$/.test(s))
          );

          const isTorExit = exits.has(clientIP);

          return json({
            ip: clientIP,
            tor: isTorExit,
            status: isTorExit ? "detected" : "clean",
            source: "Tor Project Bulk Exit List",
            checked_at: new Date().toISOString(),
            message: isTorExit
              ? "This IP is currently listed as a Tor exit node."
              : "This IP is not currently listed as a Tor exit node."
          });
        } catch {
          return json({
            error: true,
            message: "Tor check service unavailable"
          }, 502);
        }
      }

      if (vpnCheck) {
        const results = {
          iplogs: "Unavailable",
          ip99: "Unavailable",
          vpnapi: "Unavailable",
          scamalytics: "Unavailable",
          iphub: "Unavailable",
          vpndetection: "Unavailable"
        };

        // Run all independent providers in parallel. Each provider gets one retry
        // for timeouts/network errors/5xx responses, reducing random 4/6 results
        // without retrying normal 4xx API errors.
        const checks = [
          (async () => {
            try {
              const r = await fetchWithRetry("https://iplogs.com/v1/check", {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "Accept": "application/json"
                },
                body: JSON.stringify({ ip: clientIP })
              });
              if (!r.ok) return { key: "iplogs" };
              const d = await r.json();
              const yes =
                d.is_vpn === true ||
                d.verdict === "vpn_detected" ||
                d.verdict === "vpn_likely";
              return { key: "iplogs", value: yes ? "VPN" : "No VPN", detected: yes, signal: yes ? "IPLogs: VPN" : null };
            } catch {
              return { key: "iplogs" };
            }
          })(),

          (async () => {
            try {
              const headers = { "Accept": "application/json" };
              if (env.IP99_API_KEY) headers["X-API-Key"] = env.IP99_API_KEY;
              const r = await fetchWithRetry(
                `https://ip99.com/v1/ip/${encodeURIComponent(clientIP)}`,
                { headers }
              );
              if (!r.ok) return { key: "ip99" };
              const d = await r.json();
              const rs = Array.isArray(d.risk?.signals) ? d.risk.signals : [];
              const yes = rs.some(s => String(s).toLowerCase() === "vpn");
              return { key: "ip99", value: yes ? "VPN" : "No VPN", detected: yes, signal: yes ? "IP99: VPN" : null };
            } catch {
              return { key: "ip99" };
            }
          })(),

          (async () => {
            try {
              if (!env.VPNAPI_KEY) return { key: "vpnapi" };
              const r = await fetchWithRetry(
                `https://vpnapi.io/api/${encodeURIComponent(clientIP)}?key=${encodeURIComponent(env.VPNAPI_KEY)}`,
                { headers: { "Accept": "application/json" } }
              );
              if (!r.ok) return { key: "vpnapi" };
              const d = await r.json();
              const yes = d?.security?.vpn === true;
              return { key: "vpnapi", value: yes ? "VPN" : "No VPN", detected: yes, signal: yes ? "VPNAPI.io: VPN" : null };
            } catch {
              return { key: "vpnapi" };
            }
          })(),

          (async () => {
            try {
              if (!env.SCAMALYTICS_USERNAME || !env.SCAMALYTICS_API_KEY) {
                return { key: "scamalytics" };
              }

              const bases = env.SCAMALYTICS_API_BASE
                ? [env.SCAMALYTICS_API_BASE]
                : [
                    "https://api12.scamalytics.com/v3/",
                    "https://api11.scamalytics.com/v3/"
                  ];

              for (const base of bases) {
                try {
                  const endpoint =
                    base.replace(/\/+$/, "") +
                    "/" + encodeURIComponent(env.SCAMALYTICS_USERNAME) +
                    "?key=" + encodeURIComponent(env.SCAMALYTICS_API_KEY) +
                    "&ip=" + encodeURIComponent(clientIP);

                  const r = await fetchWithRetry(endpoint, {
                    headers: { "Accept": "application/json" }
                  });

                  if (!r.ok) continue;
                  const d = await r.json();
                  if (d?.scamalytics?.status !== "ok") continue;

                  const yes = d?.scamalytics?.scamalytics_proxy?.is_vpn === true;
                  return {
                    key: "scamalytics",
                    value: yes ? "VPN" : "No VPN",
                    detected: yes,
                    signal: yes ? "Scamalytics: VPN" : null
                  };
                } catch {}
              }
            } catch {}

            return { key: "scamalytics" };
          })(),

          (async () => {
            try {
              if (!env.IPHUB_API_KEY) return { key: "iphub" };

              const r = await fetchWithRetry(
                `https://v2.api.iphub.info/ip/${encodeURIComponent(clientIP)}`,
                {
                  headers: {
                    "X-Key": env.IPHUB_API_KEY,
                    "Accept": "application/json"
                  }
                }
              );

              if (!r.ok) return { key: "iphub" };
              const d = await r.json();
              const yes = Number(d?.block) === 2;
              return {
                key: "iphub",
                value: yes ? "VPN" : "No VPN",
                detected: yes,
                signal: yes ? "IPHub: VPN/Proxy/Tor" : null
              };
            } catch {
              return { key: "iphub" };
            }
          })(),

          (async () => {
            try {
              // Keep the existing key names available for compatibility, but use
              // the documented keyless endpoint already used by the site.
              const apiKey = env.VPNDETECTION_API_KEY || env.VPNDETECTION_KEY || "";
              void apiKey;

              const endpoint =
                `https://api.vpndetection.io/${encodeURIComponent(clientIP)}`;
              const r = await fetchWithRetry(endpoint, {
                headers: { "Accept": "application/json" }
              });

              if (!r.ok) return { key: "vpndetection" };
              const d = await r.json();
              const yes =
                d?.is_vpn === true ||
                d?.vpn === true ||
                d?.data?.is_vpn === true ||
                d?.data?.vpn === true;

              return {
                key: "vpndetection",
                value: yes ? "VPN" : "No VPN",
                detected: yes,
                signal: yes ? "VPNDetection.io: VPN" : null
              };
            } catch {
              return { key: "vpndetection" };
            }
          })()
        ];

        const settled = await Promise.all(checks);
        let detected = 0;
        let checked = 0;
        const signals = [];

        for (const result of settled) {
          if (!result?.key || !result.value) continue;
          results[result.key] = result.value;
          checked++;
          if (result.detected) {
            detected++;
            if (result.signal) signals.push(result.signal);
          }
        }

        let status = "clean";
        if (detected >= 2) status = "detected";
        else if (detected === 1) status = "possible";

        return json({
          ip: clientIP,
          status,
          detected_sources: detected,
          checked_sources: checked,
          total_sources: 6,
          sources: results,
          signals
        });
      }

      // IP lookup
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
              message: data.message || data.error || `IP99 error ${response.status}`
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
                isp =
                  asnData.name ||
                  asnData.organization ||
                  asnData.orgName ||
                  asnData.org ||
                  "Unknown";
              }
            } catch {}
          }

          let postal =
            data.geo?.postal_code ||
            data.geo?.postal ||
            "Unknown";

          if (postal === "Unknown") {
            try {
              const hackResponse = await safeFetch(
                `https://hackmyip.com/api/lookup?ip=${encodeURIComponent(searchedIP)}`
              );
              if (hackResponse.ok) {
                const hackResult = await hackResponse.json();
                postal =
                  hackResult?.data?.location?.postal_code ||
                  "Unknown";
                if (isp === "Unknown") {
                  isp =
                    hackResult?.data?.network?.isp ||
                    hackResult?.data?.network?.org ||
                    "Unknown";
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
          return json(
            { error: true, message: "IP lookup service unavailable" },
            502
          );
        }
      }

      // Own IP — Cloudflare
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

    const response = await env.ASSETS.fetch(request);

    const headers = new Headers(response.headers);

    headers.set(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; font-src 'self' data: https:; frame-src 'self' https:;"
    );

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers
    });
  }
};
