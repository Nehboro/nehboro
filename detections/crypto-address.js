(function () {
  NW_register({
    id: 'CRYPTO_ADDRESS_SWAP', name: 'Crypto Address in Clipboard Context',
    description: 'Cryptocurrency address found near clipboard or copy functionality',
    defaultScore: 2, tags: ['malware','crypto'],
    detect(ctx) {
      const btcAddr = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[a-zA-HJ-NP-Z0-9]{25,89}\b/;
      const ethAddr = /\b0x[a-fA-F0-9]{40}\b/;
      const hasClipboard = /clipboard|writeText|execCommand.*copy|setData/i.test(ctx.pageHTML);
      const hasCrypto = btcAddr.test(ctx.pageHTML) || ethAddr.test(ctx.pageHTML);
      if (hasCrypto && hasClipboard)
        return { description: 'Crypto address near clipboard API - possible address swap', evidence: (ctx.pageHTML.match(btcAddr) || ctx.pageHTML.match(ethAddr) || [''])[0].substring(0, 60) };
      return null;
    }
  });
})();
