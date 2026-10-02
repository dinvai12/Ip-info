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
          // 🌐 IP99 lookup
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

          // 🔢 ASN
          const asnNumber = data.network?.asn;

          // 🏢 ISP / Organization from ASN
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

          // 📮 Postal Code fallback
          let postal = "Unknown";

          // First try IP99
          if (data.geo?.postal_code) {
            postal = data.geo.postal_code;
          } else if (data.geo?.postal) {
            postal = data.geo.postal;
          }

          // If IP99 doesn't provide postal code,
          // use HackMyIP
          if (postal === "Unknown") {
            try {
              const postalResponse = await fetch(
                `https://hackmyip.com/api/lookup?ip=${encodeURIComponent(
                  searchedIP
                )}`
              );

              if (postalResponse.ok) {
                const postalData = await postalResponse.json();

                postal =
                  postalData?.location?.postal_code ||
                  postalData?.postal_code ||
                  "Unknown";
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

            // External IP searches cannot show Cloudflare colo
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

      const data = {
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
