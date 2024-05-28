// Dependencies
import { serve } from "bun";
import { readFile } from "fs/promises";

const users: { [key: string]: string } = {};

const returnHeaders = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
};

serve({
  async fetch(request) {
    const { url, method } = request;
    const { pathname } = new URL(url);

    if (pathname === "/" && method === "GET") {
      try {
        const fileContent = await readFile("app/index.html");
        return new Response(fileContent, {
          status: 200,
          headers: { "Content-Type": "text/html" },
        });
      } catch (error) {
        return new Response("Failed to load index.html", { status: 500 });
      }
    }

    if (pathname === "/api/users" && method === "GET") {
      return new Response(JSON.stringify(users), {
        status: 200,
        headers: returnHeaders,
      });
    }

    if (pathname === "/api/login" && method === "POST") {
      const { username, password } = await request.json();
      if (username in users && users[username] === password) {
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: returnHeaders,
        });
      }

      return new Response(JSON.stringify({ success: false }), {
        status: 401,
        headers: returnHeaders,
      });
    }

    if (pathname === "/api/register" && method === "POST") {
      const { username, password } = await request.json();
      if (username in users) {
        return new Response(
          JSON.stringify({ success: false, message: "User already exists" }),
          { status: 409, headers: returnHeaders }
        );
      }
      users[username] = password;
      return new Response(JSON.stringify({ success: true }), {
        status: 201,
        headers: returnHeaders,
      });
    }

    return new Response("Page not found", { status: 404 });
  },
});
console.log("Server running on port 3000");
