function normalizedAddress(value) {
  return String(value || "").trim().toLowerCase();
}

export default {
  async email(message, env) {
    const collectorAddress = normalizedAddress(env.COLLECTOR_ADDRESS);
    const destinationAddress = normalizedAddress(env.DESTINATION_ADDRESS);

    if (!collectorAddress || !destinationAddress) {
      message.setReject("DMARC collector configuration is incomplete");
      return;
    }

    if (normalizedAddress(message.to) !== collectorAddress) {
      message.setReject("Recipient is not configured for this DMARC collector");
      return;
    }

    await message.forward(
      destinationAddress,
      new Headers({
        "X-DMARQ-Collector": "cloudflare-email-relay",
        "X-DMARQ-Original-Recipient": collectorAddress,
      }),
    );
  },
};
