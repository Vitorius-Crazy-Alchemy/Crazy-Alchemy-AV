document.addEventListener('DOMContentLoaded', () => {
    chrome.runtime.sendMessage({ type: "GET_STATUS" }, (resp) => {
        if (!resp) return;
        document.getElementById('stat-threats').textContent = (resp.stats?.threats_blocked || 0).toLocaleString();
        document.getElementById('stat-ads').textContent = (resp.stats?.ads_blocked || 0).toLocaleString();

        const s = resp.settings || {};
        document.getElementById('chk-malware').checked = s.malware_protection !== false;
        document.getElementById('chk-adblock').checked = s.adblock_enabled !== false;
        document.getElementById('chk-miner').checked = s.miner_protection !== false;
    });

    function saveSettings() {
        const newSettings = {
            malware_protection: document.getElementById('chk-malware').checked,
            adblock_enabled: document.getElementById('chk-adblock').checked,
            miner_protection: document.getElementById('chk-miner').checked
        };
        chrome.runtime.sendMessage({ type: "UPDATE_SETTINGS", settings: newSettings });
    }

    document.getElementById('chk-malware').addEventListener('change', saveSettings);
    document.getElementById('chk-adblock').addEventListener('change', saveSettings);
    document.getElementById('chk-miner').addEventListener('change', saveSettings);
});