import assert from "node:assert/strict";
import test from "node:test";

import worker from "../src/index.js";

function emailMessage(to) {
  return {
    to,
    forwarded: [],
    rejected: null,
    async forward(destination, headers) {
      this.forwarded.push({ destination, headers });
    },
    setReject(reason) {
      this.rejected = reason;
    },
  };
}

const env = {
  COLLECTOR_ADDRESS: "dmarc@example.com",
  DESTINATION_ADDRESS: "reports@example.net",
};

test("forwards the configured collector recipient with trace headers", async () => {
  const message = emailMessage("DMARC@example.com");

  await worker.email(message, env);

  assert.equal(message.rejected, null);
  assert.equal(message.forwarded.length, 1);
  assert.equal(message.forwarded[0].destination, "reports@example.net");
  assert.equal(
    message.forwarded[0].headers.get("X-DMARQ-Collector"),
    "cloudflare-email-relay",
  );
  assert.equal(
    message.forwarded[0].headers.get("X-DMARQ-Original-Recipient"),
    "dmarc@example.com",
  );
});

test("rejects mail addressed to a different recipient", async () => {
  const message = emailMessage("other@example.com");

  await worker.email(message, env);

  assert.match(message.rejected, /Recipient is not configured/);
  assert.equal(message.forwarded.length, 0);
});

test("rejects mail when the relay configuration is incomplete", async () => {
  const message = emailMessage("dmarc@example.com");

  await worker.email(message, { ...env, DESTINATION_ADDRESS: "" });

  assert.match(message.rejected, /configuration is incomplete/);
  assert.equal(message.forwarded.length, 0);
});
