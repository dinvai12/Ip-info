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
          const response = await fetch(
            `https://ip99.com/v1/ip/${encodeURIComponent(searchedIP)}`,
            {
              headers: {
                "X-API-Key": env.IP99_API_KEY,
                "Accept": "application/json"
              }
            }
          );

          const text = await response.text();

          let data;

          try {
            data = JSON.parse(text);
          } catch {
            return new Response(
              JSON.stringify({
                error: true,
                message: "Invalid response from IP99"
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

          const result = {
            ip: data.ip || searchedIP,

            country:
              data.geo?.country ||
              data.country ||
              "Unknown",

            city:
              data.geo?.city ||
              data.city ||
              "Unknown",

            region:
              data.geo?.region ||
              data.region ||
              "Unknown",

            postal:
              data.geo?.postal_code ||
              data.geo?.postal ||
              data.postal_code ||
              "Unknown",

            timezone:
              data.geo?.timezone ||
              data.geo?.tz ||
              data.timezone ||
              "Unknown",

            latitude:
              data.geo?.latitude ??
              data.geo?.lat ??
              data.latitude ??
              "Unknown",

            longitude:
              data.geo?.longitude ??
              data.geo?.lon ??
              data.longitude ??
              "Unknown",

            asn:
              data.network?.asn
                ? `AS${data.network.asn}`
                : data.asn
                  ? `AS${data.asn}`
                  : "Unknown",

            isp:
              data.network?.organization ||
              data.network?.org ||
              data.organization ||
              data.org ||
              "Unknown",

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
