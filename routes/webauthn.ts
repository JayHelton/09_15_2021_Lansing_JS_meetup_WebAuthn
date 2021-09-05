import base64url from "base64url";
import crypto from 'crypto';
import {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse,
} from "@simplewebauthn/server";

import type {
  AttestationCredentialJSON,
  AssertionCredentialJSON,
  AuthenticatorDevice,
} from "@simplewebauthn/typescript-types";

import { Router } from "express";

const rpID = "localhost";
const expectedOrigin = `http://${rpID}:3000`;

const router = Router();
 
export interface LoggedInUser {
  username: string;
  password?: string;
  loggedIn: boolean;
  devices: AuthenticatorDevice[];
  currentChallenge?: string;
}

function generateUsername(): string {
    const randomBytes = crypto.randomBytes(32);
    return randomBytes.toString('hex');
}

export default function (database: any) {
  router.post("/generate-attestation-options", (req, res) => {
    let { username, requireResidentKey } = req.body;

    if (!username) {
     /**
      * When using usernameless, we generate a value to act as the userhandle
      * for the residential credential.
      */
      username = generateUsername();
    }

    const user: LoggedInUser = {
      username,
      loggedIn: false,
      devices: [],
    };

    const options = generateAttestationOptions({
      rpName: "SimpleWebAuthn Example",
      rpID,
      userID: user.username,
      userName: user.username,
      // display name is shown when the browser lists available residential credentials on
      // the webauthn compatible device
      userDisplayName: `${rpID} - ${(new Date()).toISOString()}`,
      timeout: 60000,
      attestationType: "indirect",
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: requireResidentKey ? 'required' : 'discouraged'
      },
    });

    user.currentChallenge = options.challenge;
    database[user.username] = user;

    res.cookie("user", user.username, { maxAge: 900000 });

    res.send(options);
  });

  router.post("/verify-attestation", async (req, res) => {
    const body: AttestationCredentialJSON = req.body;
    const user = database[req.cookies.user];
    const expectedChallenge = user.currentChallenge;

    let verification;

    try {
      verification = await verifyAttestationResponse({
        credential: body,
        expectedChallenge: `${expectedChallenge}`,
        expectedOrigin,
        expectedRPID: rpID,
      });
    } catch (error) {
      console.error(error);
      return res.status(400).send({ error: error.message });
    };

    const { verified, attestationInfo } = verification;

    if (verified && attestationInfo) {
      const { credentialPublicKey, credentialID, counter } = attestationInfo;

      const existingDevice = user.devices.find(
        (device) => device.credentialID === credentialID
      );

      if (!existingDevice) {
        const newDevice: AuthenticatorDevice = {
          credentialPublicKey,
          credentialID,
          counter,
        };
        user.devices.push(newDevice);
      };

      user.loggedIn = true;
      res.send({ verified });
    } else {
      res.status(401).send("unauthorized");
    }
  });

  router.post("/generate-assertion-options", (req, res) => {
    const { username } = req.body;
    let user = database[username];

    if (!user) {
     /**
      * When using passwordless, we must maintain server side data
      * in order to keep track of the stateful transaction.
      * Without a temporary data store, the challenges created would be lost
      */
      user = {
        username: generateUsername()
      }
      database[user.username] = user;
    }

    const options = generateAssertionOptions({
      timeout: 60000,
      allowCredentials: user?.devices?.map((dev) => ({
        id: dev.credentialID,
        type: "public-key",
        transports: ["usb", "ble", "nfc", "internal"],
      })),
      rpID,
    });

    user!.currentChallenge = options.challenge;
    res.cookie("user", user.username, { maxAge: 900000 });

    res.send(options);
  });

  router.post("/verify-assertion", (req, res) => {
    let dbAuthenticator;
    let user = database[req.cookies.user];

    const body: AssertionCredentialJSON = req.body;
    const expectedChallenge = user!.currentChallenge;
  
    user = database[body.response.userHandle];

    const bodyCredIDBuffer = base64url.toBuffer(body.rawId);
    for (const dev of user!.devices) {
      if (dev.credentialID.equals(bodyCredIDBuffer)) {
        dbAuthenticator = dev;
        break;
      }
    }

    if (!dbAuthenticator) {
      throw new Error(`could not find authenticator matching ${body.id}`);
    }

    let verification;

    try {
      verification = verifyAssertionResponse({
        credential: body,
        expectedChallenge: `${expectedChallenge}`,
        expectedOrigin,
        expectedRPID: rpID,
        authenticator: dbAuthenticator,
      });
    } catch (error) {
      console.error(error);
      return res.status(400).send({ error: error.message });
    }

    const { verified, assertionInfo } = verification;

    if (verified) {
      dbAuthenticator.counter = assertionInfo.newCounter;
      user.loggedIn = true;
      res.cookie("user", user.username, { maxAge: 900000 });
      res.send({ verified });
    } else {
      res.status(401).send("unauthorized");
    }
  });

  return router;
}
