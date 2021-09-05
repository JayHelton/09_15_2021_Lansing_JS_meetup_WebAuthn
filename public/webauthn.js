const { startRegistration, startAuthentication, browserSupportsWebauthn } = SimpleWebAuthnBrowser;

async function authenticateWebauthn({ username } = {}) {
  const resp = await fetch("/api/webauthn/generate-assertion-options", { 
    method: 'POST' ,
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username }),
  });

  const opts = await resp.json();
  const asseResp = await startAuthentication(opts);

  const verificationResp = await fetch("/api/webauthn/verify-assertion", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(asseResp),
  });

  return verificationResp.json();
}

async function registerWebauthn({ username, requireResidentKey } = {}) {
  const resp = await fetch("/api/webauthn/generate-attestation-options", { 
    method: 'POST' ,
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, requireResidentKey }),
  });

  const attResp = await startRegistration(await resp.json());
  const verificationResp = await fetch("/api/webauthn/verify-attestation", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(attResp),
  });

  return verificationResp.json();
}

