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

  // Standalone: page mentions multiple crypto wallets and "connect" functionality
  // (common in fake DApp / wallet drainer phishing pages, even without form input)
  NW_register({
    id: 'CRYPTO_WALLET', name: 'Crypto Wallet Connect Lure',
    description: 'Page references multiple crypto wallets with connect/sign functionality',
    defaultScore: 12, tags: ['phishing','crypto'],
    detect(ctx) {
      const text = ctx.rawText;
      const wallets = [
        /metamask/i, /phantom/i, /trust\s*wallet/i, /coinbase\s*wallet/i,
        /ledger/i, /trezor/i, /walletconnect/i, /rainbow\s*wallet/i,
      ];
      const walletHits = wallets.filter(p => p.test(text)).length;
      const hasConnect = /(?:connect\s*(?:your\s*)?wallet|sign\s*(?:this\s*)?(?:transaction|message)|approve\s*transaction|wallet\s*address)/i.test(text);
      if (walletHits >= 2 && hasConnect) {
        return {
          description: `${walletHits} crypto wallets referenced with connect/sign lure`,
          evidence: text.match(/(?:metamask|phantom|trust\s*wallet|coinbase\s*wallet)/i)?.[0] || 'wallet keywords',
          scoreBonus: walletHits >= 4 ? 10 : 0,
        };
      }
      return null;
    }
  });
})();
