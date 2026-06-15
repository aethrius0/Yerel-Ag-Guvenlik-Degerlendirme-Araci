let pollInterval = null;

function startScan() {
    const btn = document.getElementById("start-btn");
    const progressCard = document.getElementById("progress-card");
    const doneCard = document.getElementById("done-card");
    const errorCard = document.getElementById("error-card");

    // Reset
    progressCard.style.display = "block";
    doneCard.style.display = "none";
    errorCard.style.display = "none";
    btn.disabled = true;
    btn.textContent = "⏳ Taranıyor...";

    const payload = {
        network: document.getElementById("network").value,
        timeout: parseInt(document.getElementById("timeout").value),
        do_portscan: document.getElementById("do_portscan").checked,
        deep: document.getElementById("deep").checked,
        ports: document.getElementById("ports").value,
    };

    fetch("/scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    })
    .then(r => r.json())
    .then(data => {
        if (data.error) {
            showError(data.error);
            return;
        }
        pollInterval = setInterval(pollStatus, 1000);
    })
    .catch(e => showError(e.toString()));
}

function pollStatus() {
    fetch("/scan/status")
    .then(r => r.json())
    .then(data => {
        // Progress bar guncelle
        const bar = document.getElementById("progress-bar");
        bar.style.width = (data.progress * 100) + "%";

        // Metinler
        const stageEl = document.getElementById("progress-stage");
        const msgEl = document.getElementById("progress-message");

        const stageNames = {
            discovery: "🔍 Cihaz Keşfi",
            portscan: "🔌 Port Tarama",
            naming: "🏷️ İsim Tespiti",
            classify: "📂 Sınıflandırma",
            evaluate: "🛡️ Güvenlik Değerlendirmesi",
            done: "✅ Tamamlandı",
        };

        stageEl.textContent = stageNames[data.stage] || data.stage;
        msgEl.textContent = data.message;

        if (data.sub) {
            msgEl.textContent += ` (${data.sub[0]}/${data.sub[1]})`;
        }

        if (data.done) {
            clearInterval(pollInterval);
            document.getElementById("progress-card").style.display = "none";
            document.getElementById("done-card").style.display = "block";
            document.getElementById("start-btn").disabled = false;
            document.getElementById("start-btn").textContent = "▶ Taramayı Başlat";
        }

        if (data.error) {
            clearInterval(pollInterval);
            showError(data.error);
        }
    });
}

function showError(msg) {
    document.getElementById("progress-card").style.display = "none";
    document.getElementById("error-card").style.display = "block";
    document.getElementById("error-message").textContent = msg;
    document.getElementById("start-btn").disabled = false;
    document.getElementById("start-btn").textContent = "▶ Taramayı Başlat";
}

function toggleDetail(id) {
    const row = document.getElementById(id);
    row.style.display = row.style.display === "none" ? "table-row" : "none";
}
