// Crazy Alchemy Brave-Style In-Page AdBlock & Miner Neutralizer
(function() {
    'use strict';

    // 1. Inject Brave-style cosmetic element hiding CSS
    const style = document.createElement('style');
    style.id = 'crazy-alchemy-adblock-styles';
    style.textContent = `
        .ad-container, .ad-banner, .advertisement, .adsbygoogle,
        [id*="google_ads"], [class*="google-ad"], [id*="taboola-"],
        [id*="outbrain_"], [class*="sponsored-post"], [class*="native-ad"],
        iframe[src*="doubleclick"], iframe[src*="adroll"], iframe[src*="amazon-adsystem"],
        div[data-ad-unit], div[data-ad-slot], div[class*="ad_wrapper"],
        div[class*="ad-slot"], div[id*="ad_banner"], div[id*="adv_box"] {
            display: none !important;
            visibility: hidden !important;
            height: 0px !important;
            width: 0px !important;
            max-height: 0px !important;
            pointer-events: none !important;
            opacity: 0 !important;
        }
    `;
    (document.head || document.documentElement).appendChild(style);

    // 2. Cryptominer Neutralizer (traps WebAssembly mining loops)
    if (window.CoinHive) window.CoinHive = undefined;
    if (window.CryptoLoot) window.CryptoLoot = undefined;

    // 3. Scan and count hidden ad elements to report statistics
    let reportedAds = 0;
    function scanAndCountAds() {
        const adElements = document.querySelectorAll(
            '.adsbygoogle, [id*="google_ads"], iframe[src*="doubleclick"], [class*="sponsored-post"]'
        );
        if (adElements.length > reportedAds) {
            const delta = adElements.length - reportedAds;
            reportedAds = adElements.length;
            chrome.runtime.sendMessage({ type: "ADS_BLOCKED_REPORT", count: delta }, () => {
                if (chrome.runtime.lastError) {}
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', scanAndCountAds);
    } else {
        scanAndCountAds();
    }
    setInterval(scanAndCountAds, 4000);
})();