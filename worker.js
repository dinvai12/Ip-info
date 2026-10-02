export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // IP API
    if (url.pathname === "/api") {

      const searchedIP = url.searchParams.get("ip");

      // 🔎 Search for another IP
      if (searchedIP) {

        // Basic IP input validation
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
          const apiURL =
            `https://ipapi.co/${encodeURIComponent(searchedIP)}/json/`;

          const response = await fetch(apiURL);

          const data = await response.json();

          if (data.error) {
            return new Response(
              JSON.stringify({
                error: true,
                message: data.reason || "IP lookup failed"
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

          return new Response(
            JSON.stringify({
              ip: data.ip || "Unknown",
              country: data.country_code || data.country || "Unknown",
              city: data.city || "Unknown",
              region: data.region || "Unknown",
              postal: data.postal || "Unknown",
              timezone: data.timezone || "Unknown",
              latitude: data.latitude ?? "Unknown",
              longitude: data.longitude ?? "Unknown",
              asn: data.asn || "Unknown",
              isp: data.org || "Unknown",
              colo: "N/A"
            }),
            {
              headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
              }
            }
          );

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

      // 🌐 Visitor's own IP
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
        asn: cf.asn || "Unknown",
        isp: cf.asOrganization || "Unknown",
        colo: cf.colo || "Unknown"
      };

      return new Response(
        JSON.stringify(data),
        {
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          }
        }
      );
    }

    // Website
    return env.ASSETS.fetch(request);
  }
};
