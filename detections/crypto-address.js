(function () {
  const BTC_ADDR = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[a-zA-HJ-NP-Z0-9]{25,89}\b/g;
  const ETH_ADDR = /\b0x[a-fA-F0-9]{40}\b/g;
  const SOL_ADDR = /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g;
  const XMR_ADDR = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g;

  NW_register({
    id: 'CRYPTO_ADDRESS_SWAP', name: 'Crypto Address in Clipboard Context',
    description: 'Cryptocurrency address found near clipboard or copy functionality',
    defaultScore: 2, tags: ['malware','crypto'],
    detect(ctx) {
      const hasClipboard = /clipboard|writeText|execCommand.*copy|setData/i.test(ctx.pageHTML);
      const hasCrypto = BTC_ADDR.test(ctx.pageHTML) || ETH_ADDR.test(ctx.pageHTML);
      if (hasCrypto && hasClipboard) {
        BTC_ADDR.lastIndex = 0; ETH_ADDR.lastIndex = 0;
        return { description: 'Crypto address near clipboard API - possible address swap', evidence: (ctx.pageHTML.match(BTC_ADDR) || ctx.pageHTML.match(ETH_ADDR) || [''])[0].substring(0, 60) };
      }
      return null;
    }
  });

  // Standalone: page contains multiple crypto wallet addresses (payment/donation pages, scams)
  NW_register({
    id: 'CRYPTO_ADDRESSES_LISTED', name: 'Multiple Crypto Wallet Addresses',
    description: 'Page lists multiple cryptocurrency wallet addresses (payment-required scams)',
    defaultScore: 18, tags: ['malware','crypto'],
    detect(ctx) {
      const text = ctx.rawText + ' ' + ctx.pageHTML;
      const btcMatches = (text.match(BTC_ADDR) || []).slice(0, 5);
      const ethMatches = (text.match(ETH_ADDR) || []).slice(0, 5);
      const types = [];
      if (btcMatches.length > 0) types.push('BTC');
      if (ethMatches.length > 0) types.push('ETH');

      // Count distinct addresses
      const allAddrs = new Set([...btcMatches, ...ethMatches]);
      // Also detect address mentions by symbol/name (Solana, Monero often use other formats)
      const altCryptoMentions = (text.match(/\b(?:bitcoin|ethereum|solana|monero|litecoin|dogecoin|usdt|usdc|tron|xrp|btc|eth|sol|xmr|ltc|doge)\b/gi) || []).length;

      if (allAddrs.size >= 2) {
        return {
          description: `${allAddrs.size} crypto addresses (${types.join(', ')}) on page`,
          evidence: [...allAddrs].slice(0, 2).map(a => a.substring(0, 30)).join(', '),
          scoreBonus: allAddrs.size >= 3 ? 12 : 0,
        };
      }
      if (allAddrs.size === 1 && altCryptoMentions >= 4) {
        return {
          description: `Crypto address with ${altCryptoMentions} crypto-related mentions`,
          evidence: [...allAddrs][0].substring(0, 40),
          scoreOverride: 10,
        };
      }
      return null;
    }
  });
})();
