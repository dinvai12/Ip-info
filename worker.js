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
            `https://ip99.com/v1/ip/${encodeURIComponent(searchedIP)}`
          );

          const data = await response.json();

          if (!response.ok || data.error) {
            return new Response(
              JSON.stringify({
                error: true,
                message:
                  data.error?.message ||
                  `IP lookup failed (${response.status})`
              }),
              {
                status: response.status || 502,
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
              "Unknown",

            city:
              data.geo?.city ||
              "Unknown",

            region:
              data.geo?.region ||
              "Unknown",

            postal:
              data.geo?.postal_code ||
              data.geo?.postal ||
              "Unknown",

            timezone:
              data.geo?.tz ||
              data.geo?.timezone ||
              "Unknown",

            latitude:
              data.geo?.lat ??
              "Unknown",

            longitude:
              data.geo?.lon ??
              "Unknown",

            asn:
              data.network?.asn
                ? `AS${data.network.asn}`
                : "Unknown",

            isp:
              data.network?.organization ||
              data.network?.org ||
              data.network?.asn_org ||
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
