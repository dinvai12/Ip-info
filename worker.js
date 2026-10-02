export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api") {
      const searchedIP = url.searchParams.get("ip");

      // Search another IP
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
          const apiURL =
            `https://free.freeipapi.com/api/v1/json/${searchedIP}`;

          const response = await fetch(apiURL, {
            method: "GET",
            headers: {
              "Accept": "application/json"
            }
          });

          const body = await response.text();

          if (!response.ok) {
            return new Response(
              JSON.stringify({
                error: true,
                message: `FreeIPAPI HTTP ${response.status}`,
                details: body.substring(0, 200)
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

          let data;

          try {
            data = JSON.parse(body);
          } catch {
            return new Response(
              JSON.stringify({
                error: true,
                message: "FreeIPAPI returned non-JSON response",
                details: body.substring(0, 200)
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

          return new Response(
            JSON.stringify({
              ip: data.ipAddress || searchedIP,
              country: data.countryCode || "Unknown",
              city: data.cityName || "Unknown",
              region: data.regionName || "Unknown",
              postal: data.zipCode || "Unknown",
              timezone:
                Array.isArray(data.timeZones)
                  ? data.timeZones[0] || "Unknown"
                  : data.timeZones || "Unknown",
              latitude: data.latitude ?? "Unknown",
              longitude: data.longitude ?? "Unknown",
              asn: data.asn ? `AS${data.asn}` : "Unknown",
              isp: data.asnOrganization || "Unknown",
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
              message: "Worker could not reach FreeIPAPI"
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

      // Your own IP
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
