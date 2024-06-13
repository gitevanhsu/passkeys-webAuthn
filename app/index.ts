import { serve } from "bun";
import { readFile } from "fs/promises";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type VerifiedRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticatorTransportFuture,
  CredentialDeviceType,
  Base64URLString,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/types";

type Passkey = {
  id: Base64URLString;
  publicKey: Uint8Array;
  user: { id: Uint8Array; username: string };
  counter: number;
  deviceType: CredentialDeviceType;
  backedUp: boolean;
  transports?: AuthenticatorTransportFuture[];
};

const rpID = "localhost";
const origin = `http://${rpID}:3000`;

interface IUserInfo {
  username: string;
  password: string;
  id: Uint8Array;
  userPasskeys: Array<Passkey>;
  currentRegistrationOptions?: PublicKeyCredentialCreationOptionsJSON;
  currentAuthenticationOptions?: PublicKeyCredentialRequestOptionsJSON;
}

// store user information
const USER_INFO_MAP: Record<string, IUserInfo> = {};

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

    if (pathname === "/api/login" && method === "POST") {
      const { username, password } = await request.json();

      if (
        username in USER_INFO_MAP &&
        USER_INFO_MAP[username].password === password
      ) {
        return new Response(
          JSON.stringify({ user: USER_INFO_MAP[username].username }),
          { status: 200 }
        );
      }

      if (
        username in USER_INFO_MAP &&
        USER_INFO_MAP[username].password !== password
      ) {
        return new Response(JSON.stringify({ message: "Wrong password!" }), {
          status: 401,
        });
      }

      if (!(username in USER_INFO_MAP)) {
        return new Response(
          JSON.stringify({ message: "User not registered!" }),
          { status: 401 }
        );
      }

      return new Response(JSON.stringify({ message: "Something wrong!" }), {
        status: 401,
      });
    }

    if (pathname === "/api/register" && method === "POST") {
      const { username, password }: Record<string, string> =
        await request.json();
      if (username in USER_INFO_MAP) {
        return new Response(
          JSON.stringify({ message: "User already exists" }),
          { status: 409 }
        );
      }
      const id = Uint8Array.from(username, (c) => c.charCodeAt(0));
      USER_INFO_MAP[username] = { password, username, id, userPasskeys: [] };

      return new Response(
        JSON.stringify({ user: USER_INFO_MAP[username].username }),
        { status: 200 }
      );
    }

    if (pathname === "/api/webAuthn/register" && method === "POST") {
      const { username = "" } = await request.json();
      if (!username)
        return new Response(
          JSON.stringify({ message: "Please provide username" }),
          { status: 401 }
        );
      if (!USER_INFO_MAP[username]) {
        return new Response(
          JSON.stringify({ message: "User not registered!" }),
          { status: 401 }
        );
      }

      const user = USER_INFO_MAP[username];

      const options: PublicKeyCredentialCreationOptionsJSON =
        await generateRegistrationOptions({
          rpName: "Local Web Authn Test",
          rpID,
          userName: user.username,
          attestationType: "none",
          excludeCredentials: (user.userPasskeys ?? []).map((passkey) => ({
            id: passkey.id,
            transports: passkey.transports,
          })),
          authenticatorSelection: {
            residentKey: "preferred",
            userVerification: "preferred",
            authenticatorAttachment: "platform",
          },
        });

      USER_INFO_MAP[username].currentRegistrationOptions = options;

      return new Response(JSON.stringify({ options: options }), {
        status: 200,
      });
    }

    if (pathname === "/api/webAuthn/verify-registration" && method === "POST") {
      const { username, body } = await request.json();
      const user = USER_INFO_MAP[username];
      let verification: VerifiedRegistrationResponse;
      try {
        verification = await verifyRegistrationResponse({
          response: body,
          expectedChallenge: user.currentRegistrationOptions!.challenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
        });
      } catch (_error) {
        const error = _error as Error;
        return new Response(JSON.stringify({ message: error.message }), {
          status: 400,
        });
      }

      const { registrationInfo } = verification;
      const {
        credentialID,
        credentialPublicKey,
        counter,
        credentialDeviceType,
        credentialBackedUp,
      } = registrationInfo!;

      const newPasskey = {
        user,
        webAuthnUserID: user.currentRegistrationOptions!.user.id,
        id: credentialID,
        publicKey: credentialPublicKey,
        counter,
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        transports: body.response.transports,
      };

      USER_INFO_MAP[username].userPasskeys.push(newPasskey);
      const { verified } = verification;
      return new Response(JSON.stringify({ verified }), {
        status: 200,
      });
    }

    if (pathname === "/api/webAuthn/login" && method === "POST") {
      const { username } = await request.json();
      if (!username)
        return new Response(
          JSON.stringify({ message: "Please provide username" }),
          { status: 401 }
        );
      if (!USER_INFO_MAP[username]) {
        return new Response(
          JSON.stringify({ message: "User not registered!" }),
          { status: 401 }
        );
      }

      const user = USER_INFO_MAP[username];

      const userPasskeys = user.userPasskeys ?? [];
      const options: PublicKeyCredentialRequestOptionsJSON =
        await generateAuthenticationOptions({
          rpID,
          allowCredentials: userPasskeys.map((passkey) => ({
            id: passkey.id,
            transports: passkey.transports,
          })),
        });

      USER_INFO_MAP[username].currentAuthenticationOptions = options;

      return new Response(JSON.stringify({ options: options }), {
        status: 200,
      });
    }

    if (
      pathname === "/api/webAuthn/verify-authentication" &&
      method === "POST"
    ) {
      const { username, body } = await request.json();

      const user = USER_INFO_MAP[username];
      const currentOptions: PublicKeyCredentialRequestOptionsJSON =
        user.currentAuthenticationOptions!;
      const passkey: Passkey | undefined = user.userPasskeys.find(
        ({ id }) => id === body.id
      );

      if (!passkey) {
        throw new Error(
          `Could not find passkey ${body.id} for user ${user.id}`
        );
      }

      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response: body,
          expectedChallenge: currentOptions.challenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
          authenticator: {
            credentialID: passkey.id,
            credentialPublicKey: passkey.publicKey,
            counter: passkey.counter,
            transports: passkey.transports,
          },
        });
      } catch (_error) {
        const error = _error as Error;
        return new Response(JSON.stringify({ message: error.message }), {
          status: 400,
        });
      }
      const { verified } = verification;
      return new Response(JSON.stringify({ verified }), {
        status: 200,
      });
    }

    return new Response("Page not found", { status: 404 });
  },
});
console.log("Server running on port http://localhost:3000");
