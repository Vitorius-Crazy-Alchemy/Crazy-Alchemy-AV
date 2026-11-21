// Crazy Alchemy Web Shield & Crazy AdBlock Service Worker
const COMPANION_URL = "http://127.0.0.1:49211";
let settings = {
    malware_protection: true,
    adblock_enabled: true,
    miner_protection: true,
    whitelist: []
};
let stats = {
    threats_blocked: 0,
    ads_blocked: 0
};

// Load stats & settings from storage
chrome.storage.local.get(["settings", "stats"], (res) => {
    if (res.settings) Object.assign(settings, res.settings);
    if (res.stats) Object.assign(stats, res.stats);
});

// Periodic heartbeat with Crazy Alchemy Desktop
async function pingCompanion() {
    try {
        const resp = await fetch(`${COMPANION_URL}/api/status`);
        if (resp.ok) {
            chrome.action.setBadgeText({ text: "ON" });
            chrome.action.setBadgeBackgroundColor({ color: "#2e7d32" }); // Green
        }
    } catch (e) {
        chrome.action.setBadgeText({ text: "LOC" });
        chrome.action.setBadgeBackgroundColor({ color: "#e65100" }); // Orange (local mode)
    }
}
setInterval(pingCompanion, 15000);
pingCompanion();

// Intercept navigations for Malware / Phishing Defense
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === "loading" && tab.url && tab.url.startsWith("http")) {
        if (!settings.malware_protection) return;

        try {
            const urlObj = new URL(tab.url);
            const domain = urlObj.hostname.toLowerCase();

            // Check if whitelisted
            if (settings.whitelist.includes(domain)) return;

            // Query Crazy Alchemy local engine
            let blocked = false;
            let reason = "Malicious domain";
            let category = "malware";

            try {
                const checkRes = await fetch(`${COMPANION_URL}/api/check_url`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url: tab.url, domain: domain })
                });
                if (checkRes.ok) {
                    const data = await checkRes.json();
                    if (data.blocked) {
                        blocked = true;
                        reason = data.reason || reason;
                        category = data.category || category;
                    }
                }
            } catch (err) {
                // Standalone local check fallback
                const knownBad = ["malware-traffic-analysis.net", "testmalware.com", "crypto-drainer.click", "phishing-bank-login.xyz"];
                if (knownBad.some(b => domain.includes(b))) {
                    blocked = true;
                    category = "malware";
                }
            }

            if (blocked) {
                stats.threats_blocked++;
                chrome.storage.local.set({ stats });

                // Redirect tab to built-in blocked warning page
                const blockedUrl = chrome.runtime.getURL("blocked.html") + 
                    `?url=${encodeURIComponent(tab.url)}&reason=${encodeURIComponent(reason)}&category=${encodeURIComponent(category)}`;
                chrome.tabs.update(tabId, { url: blockedUrl });

                // Report threat to desktop companion
                try {
                    fetch(`${COMPANION_URL}/api/report_threat`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ url: tab.url, domain, threat_type: category, reason })
                    }).catch(() => {});
                } catch(e) {}
            }
        } catch (e) {}
    }
});

// Listen for messages from content.js and popup.js
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "ADS_BLOCKED_REPORT") {
        const count = msg.count || 1;
        stats.ads_blocked += count;
        chrome.storage.local.set({ stats });
        sendResponse({ success: true, total: stats.ads_blocked });
    } else if (msg.type === "GET_STATUS") {
        sendResponse({ settings, stats });
    } else if (msg.type === "UPDATE_SETTINGS") {
        Object.assign(settings, msg.settings);
        chrome.storage.local.set({ settings });
        sendResponse({ success: true, settings });
    }
    return true;
});