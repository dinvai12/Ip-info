export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api") {
      const searchedIP = url.searchParams.get("ip");

      // 🔎 Search another IP
      if (searchedIP) {
        if (
          searchedIP.length > 45 ||
          !/^[0-9a-fA-F:.]+$/.test(searchedIP)
        ) {
          return new Response(
            JSON.stringify({
              error: true,
              message: "Invalid IP address"
            }),
            {
              status: 400,
              headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
              }
            }
          );
        }

        try {
          // 🌐 IP99
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
            return new Response(
              JSON.stringify({
                error: true,
                message:
                  data.message ||
                  data.error ||
                  `IP99 error ${response.status}`
              }),
              {
                status: response.status,
                headers: {
                  "Content-Type": "application/json",
                  "Access-Control-Allow-Origin": "*"
                }
              }
            );
          }

          // 🛡️ VPN / Proxy detection from IP99 risk signals
          const riskSignals = Array.isArray(data.risk?.signals)
            ? data.risk.signals.map(String).map(s => s.toLowerCase())
            : [];

          const vpnDetected = riskSignals.includes("vpn");
          const proxyDetected = riskSignals.includes("proxy");

          let vpnProxy = "NO";
          let vpnProxyType = "None detected";

          if (vpnDetected && proxyDetected) {
            vpnProxy = "YES";
            vpnProxyType = "VPN + Proxy";
          } else if (vpnDetected) {
            vpnProxy = "YES";
            vpnProxyType = "VPN";
          } else if (proxyDetected) {
            vpnProxy = "YES";
            vpnProxyType = "Proxy";
          }

          // 🔢 ASN
          const asnNumber = data.network?.asn;

          // 🏢 ISP
          let isp = "Unknown";

          if (asnNumber) {
            try {
              const asnResponse = await fetch(
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
            } catch {
              isp = "Unknown";
            }
          }

          // 📮 Postal Code
          let postal = "Unknown";

          // First: IP99
          postal =
            data.geo?.postal_code ||
            data.geo?.postal ||
            "Unknown";

          // Fallback: HackMyIP
          if (postal === "Unknown") {
            try {
              const hackResponse = await fetch(
                `https://hackmyip.com/api/lookup?ip=${encodeURIComponent(
                  searchedIP
                )}`
              );

              if (hackResponse.ok) {
                const hackResult = await hackResponse.json();

                postal =
                  hackResult?.data?.location?.postal_code ||
                  "Unknown";

                // If LookIP failed, use HackMyIP ISP
                if (isp === "Unknown") {
                  isp =
                    hackResult?.data?.network?.isp ||
                    hackResult?.data?.network?.org ||
                    "Unknown";
                }
              }
            } catch {
              postal = "Unknown";
            }
          }

          // 📦 Final result
          const result = {
            ip: data.ip || searchedIP,

            country:
              data.geo?.country || "Unknown",

            city:
              data.geo?.city || "Unknown",

            region:
              data.geo?.region || "Unknown",

            postal: postal,

            timezone:
              data.geo?.tz ||
              data.geo?.timezone ||
              "Unknown",

            latitude:
              data.geo?.lat ??
              data.geo?.latitude ??
              "Unknown",

            longitude:
              data.geo?.lon ??
              data.geo?.longitude ??
              "Unknown",

            asn:
              asnNumber != null
                ? `AS${asnNumber}`
                : "Unknown",

            isp: isp,

            vpnProxy: vpnProxy,
            vpnProxyType: vpnProxyType,

            colo: "N/A"
          };

          return new Response(JSON.stringify(result), {
            headers: {
              "Content-Type": "application/json",
              "Access-Control-Allow-Origin": "*"
            }
          });

        } catch (error) {
          return new Response(
            JSON.stringify({
              error: true,
              message: "IP lookup service unavailable"
            }),
            {
              status: 502,
              headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
              }
            }
          );
        }
      }

      // 🌐 Visitor's own IP — Cloudflare
      const cf = request.cf || {};
      const visitorIP = request.headers.get("CF-Connecting-IP") || "Unknown";

      let vpnProxy = "Unknown";
      let vpnProxyType = "Detection unavailable";

      // Use IP99 risk data for the visitor's public IP.
      if (visitorIP !== "Unknown") {
        try {
          const riskResponse = await fetch(
            `https://ip99.com/v1/ip/${encodeURIComponent(visitorIP)}`,
            {
              headers: {
                "X-API-Key": env.IP99_API_KEY,
                "Accept": "application/json"
              }
            }
          );

          if (riskResponse.ok) {
            const riskData = await riskResponse.json();
            const signals = Array.isArray(riskData.risk?.signals)
              ? riskData.risk.signals.map(String).map(s => s.toLowerCase())
              : [];

            const hasVPN = signals.includes("vpn");
            const hasProxy = signals.includes("proxy");

            if (hasVPN && hasProxy) {
              vpnProxy = "YES";
              vpnProxyType = "VPN + Proxy";
            } else if (hasVPN) {
              vpnProxy = "YES";
              vpnProxyType = "VPN";
            } else if (hasProxy) {
              vpnProxy = "YES";
              vpnProxyType = "Proxy";
            } else {
              vpnProxy = "NO";
              vpnProxyType = "None detected";
            }
          }
        } catch {
          // Keep Unknown if the risk lookup fails.
        }
      }

      const data = {
        ip: visitorIP,
        country: cf.country || "Unknown",
        city: cf.city || "Unknown",
        region: cf.region || "Unknown",
        postal: cf.postalCode || "Unknown",
        timezone: cf.timezone || "Unknown",
        latitude: cf.latitude || "Unknown",
        longitude: cf.longitude || "Unknown",
        asn: cf.asn ? `AS${cf.asn}` : "Unknown",
        isp: cf.asOrganization || "Unknown",
        vpnProxy: vpnProxy,
        vpnProxyType: vpnProxyType,
        colo: cf.colo || "Unknown"
      };

      return new Response(JSON.stringify(data), {
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        }
      });
    }

    return env.ASSETS.fetch(request);
  }
};
