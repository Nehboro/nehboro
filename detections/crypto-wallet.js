(function () {
  NW_register({
    id: 'CRYPTO_WALLET_PHISHING', name: 'Crypto Wallet Phishing',
    description: 'Page requests seed phrase / private key entry',
    defaultScore: 45, tags: ['phishing','critical'],
    detect(ctx) {
      const hasSeedInput = /(?:seed|recovery|mnemonic)\s*(?:phrase|words?)/i.test(ctx.rawText);
      const hasPrivKey   = /(?:private|secret)\s*key/i.test(ctx.rawText) && ctx.hasPwdField;
      const hasWallet    = /(?:wallet|metamask|phantom|ledger|trezor)/i.test(ctx.rawText);
      if ((hasSeedInput || hasPrivKey) && hasWallet && ctx.inputCount >= 2)
        return { description: 'Crypto wallet seed phrase / private key harvesting', evidence: `Wallet keywords + ${ctx.inputCount} input fields` };
      return null;
    }
  });
})();
