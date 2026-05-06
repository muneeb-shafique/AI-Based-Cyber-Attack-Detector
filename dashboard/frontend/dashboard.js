// ============================================================
// THREAT VISION Dashboard — dashboard.js
// Connects to FastAPI backend at /api/v1/*
// ============================================================

(function () {
  "use strict";

  let isEngineRunning = false;

  // ── 3D Globe Threat Map ────────────────────────────────────
  const globeContainer = document.getElementById("globe-container");
  let world;
  let arcsData = [];
  
  if (typeof Globe !== 'undefined' && globeContainer) {
      world = Globe()
        (globeContainer)
        .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
        .backgroundColor('rgba(0,0,0,0)') // transparent to see grid background
        .width(window.innerWidth)
        .height(window.innerHeight)
        .pointOfView({ lat: 39.8, lng: -98.5, altitude: 2.5 }) // USA view
        .arcColor(() => 'rgba(255, 0, 60, 0.9)')
        .arcDashLength(0.4)
        .arcDashGap(0.2)
        .arcDashAnimateTime(1500)
        .arcsTransitionDuration(0)
        .arcStroke(1);
        
      window.addEventListener("resize", function() {
          if(world) world.width(window.innerWidth).height(window.innerHeight);
      });

      // Auto-rotate slowly
      world.controls().autoRotate = true;
      world.controls().autoRotateSpeed = 0.5;
  }

  // ── DOM Refs ─────────────────────────────────────────────
  var btnToggle      = document.getElementById("btn-toggle-engine");
  var statusDot      = document.getElementById("status-dot");
  var statusText     = document.getElementById("status-text");
  var streamBadge    = document.getElementById("stream-badge");
  var offlineBanner  = document.getElementById("offline-banner");
  var toastEl        = document.getElementById("toast");
  var alertsContainer = document.getElementById("alerts-container");
  var llmText        = document.getElementById("llm-text");
  var packetLog      = document.getElementById("packet-log");

  // ── State ────────────────────────────────────────────────
  var serverOnline   = false;
  var pendingToggle  = false;
  var displayedAlerts = {};
  var isTyping       = false;
  var currentLlmMsg  = "";

  // ── Toast ────────────────────────────────────────────────
  function showToast(msg) {
    toastEl.innerText = msg;
    toastEl.classList.add("show");
    setTimeout(function () { toastEl.classList.remove("show"); }, 3500);
  }

  // ── Status Fetch ─────────────────────────────────────────
  function fetchStatus() {
    fetch("/api/v1/status")
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (data) {
        isEngineRunning = data.is_running;
        serverOnline = true;
        if (offlineBanner) offlineBanner.classList.remove("show");
        if (!pendingToggle) updateUIPerStatus();
      })
      .catch(function () {
        serverOnline = false;
        isEngineRunning = false;
        if (offlineBanner) offlineBanner.classList.add("show");
        if (!pendingToggle) updateUIPerStatus();
      });
  }

  // ── UI Update ────────────────────────────────────────────
  function updateUIPerStatus() {
    if (isEngineRunning) {
      btnToggle.innerText = "STOP ENGINE";
      btnToggle.className = "btn active";
      statusDot.style.background = "var(--green)";
      statusDot.style.boxShadow = "0 0 10px var(--green)";
      statusDot.style.animation = "pulse 2s infinite";
      statusText.innerText = "ACTIVE";
      statusText.style.color = "var(--green)";
      streamBadge.innerText = "LIVE";
      streamBadge.style.color = "var(--cyan)";
    } else {
      btnToggle.innerText = "START ENGINE";
      btnToggle.className = "btn inactive";
      statusDot.style.background = "var(--text-dim)";
      statusDot.style.boxShadow = "none";
      statusDot.style.animation = "none";
      statusText.innerText = "IDLE";
      statusText.style.color = "var(--text-dim)";
      streamBadge.innerText = "PAUSED";
      streamBadge.style.color = "var(--text-dim)";
    }
  }

  // ── Engine Toggle Button ─────────────────────────────────
  btnToggle.addEventListener("click", function () {
    if (pendingToggle) return;
    if (!serverOnline) {
      showToast("Backend offline — run: python main.py dashboard");
      return;
    }

    pendingToggle = true;
    btnToggle.innerText = "CONNECTING...";
    btnToggle.className = "btn loading";

    var stopping = isEngineRunning;
    var endpoint = stopping ? "/api/v1/detect/stop" : "/api/v1/detect/start";
    var options = stopping
      ? { method: "POST" }
      : {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mode: "live", target: "all" })
        };

    fetch(endpoint, options)
      .then(function (r) {
        if (!r.ok) return r.text().then(function (t) { throw new Error(t); });
        // Poll until state flips (max 4 s)
        var attempts = 0;
        var poll = setInterval(function () {
          fetchStatus();
          attempts++;
          if (isEngineRunning !== stopping || attempts > 8) {
            clearInterval(poll);
            pendingToggle = false;
            updateUIPerStatus();
          }
        }, 500);
      })
      .catch(function (e) {
        showToast("Engine error: " + e.message);
        pendingToggle = false;
        fetchStatus();
      });
  });

  // ── Typewriter ───────────────────────────────────────────
  function typeWriter(text) {
    if (isTyping || text === currentLlmMsg) return;
    isTyping = true;
    currentLlmMsg = text;
    llmText.innerHTML = '<span class="cursor"></span>';
    var i = 0;
    function tick() {
      if (i < text.length) {
        llmText.innerHTML = text.substring(0, i + 1) + '<span class="cursor"></span>';
        i++;
        setTimeout(tick, Math.random() * 15 + 10);
      } else {
        isTyping = false;
      }
    }
    tick();
  }

  // ── Format time ──────────────────────────────────────────
  function formatTime(iso) {
    var d = new Date(iso);
    var hh = String(d.getHours()).padStart(2, "0");
    var mm = String(d.getMinutes()).padStart(2, "0");
    var ss = String(d.getSeconds()).padStart(2, "0");
    var ms = String(d.getMilliseconds()).padStart(3, "0");
    return hh + ":" + mm + ":" + ss + "." + ms;
  }

  // ── Alerts Fetch ─────────────────────────────────────────
  function fetchAlerts() {
    if (!isEngineRunning) return;
    fetch("/api/v1/alerts")
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data.alerts || data.alerts.length === 0) return;
        var latest = data.alerts[0];
        if (latest.llm_analysis) typeWriter(latest.llm_analysis);

        data.alerts.forEach(function (alert) {
          var alertId = alert.timestamp + alert.source_ip;
          if (displayedAlerts[alertId]) return;
          displayedAlerts[alertId] = true;

          var isCrit = alert.severity === "CRITICAL" || alert.severity === "HIGH";
          var div = document.createElement("div");
          div.className = "alert-card" + (isCrit ? " critical" : "");
          div.onclick = (function (a) {
            return function () {
              if (a.llm_analysis) {
                isTyping = false;
                setTimeout(function () { typeWriter("[ARCHIVED] " + a.llm_analysis); }, 50);
              }
            };
          })(alert);

          var conf = (alert.confidence * 100).toFixed(1);
          var typeClass = isCrit ? "alert-type alert-critical-txt" : "alert-type";
          
          var mitreHtml = (alert.mitre_technique && alert.mitre_technique !== 'Unmapped') 
            ? '<div style="color:var(--purple);font-size:0.65rem;margin-top:2px;">MITRE: ' + alert.mitre_technique + '</div>' 
            : '';
            
          var osintHtml = (alert.osint_tags && alert.osint_tags.length > 0)
            ? '<div style="color:var(--cyan);font-size:0.65rem;margin-top:2px;">OSINT: ' + alert.osint_tags.join(', ') + '</div>'
            : '';

          div.innerHTML =
            '<div class="alert-meta">' +
              "<span>" + formatTime(alert.timestamp) + "</span>" +
              "<span>CONF: " + conf + "%</span>" +
            "</div>" +
            '<div class="' + typeClass + '">[' + alert.severity + "] " + alert.attack_type + "</div>" +
            mitreHtml + 
            osintHtml +
            '<div style="margin-top:5px;">SRC: ' + alert.source_ip + "</div>" +
            "<div>DST: " + alert.dest_ip + "</div>" +
            '<div style="margin-top:5px;color:var(--text-dim);font-size:0.65rem;">ACTION: ' + alert.recommended + "</div>";

          alertsContainer.prepend(div);
          if (alertsContainer.children.length > 50) {
            alertsContainer.removeChild(alertsContainer.lastChild);
          }
          // Spawn 3D Globe Arc
          if (world) {
              const serverLat = 39.8, serverLng = -98.5; // US Server
              const attackerLat = (Math.random() - 0.5) * 160;
              const attackerLng = (Math.random() - 0.5) * 360;
              arcsData.push({
                  startLat: attackerLat,
                  startLng: attackerLng,
                  endLat: serverLat,
                  endLng: serverLng
              });
              if (arcsData.length > 25) arcsData.shift();
              world.arcsData([...arcsData]);
          }
        });
      })
      .catch(function () {});
  }

  // ── Metrics Fetch ────────────────────────────────────────────
  function fetchMetrics() {
    if (!isEngineRunning) {
      document.getElementById("m-cpu").innerText        = "0.0%";
      document.getElementById("m-lat").innerText        = "0 ms";
      document.getElementById("m-throughput").innerText = "0.00 MB/s";
      document.getElementById("m-flows").innerText      = "0";
      document.getElementById("m-threats").innerText    = "0";
      document.getElementById("m-benign").innerText     = "0";
      return;
    }
    fetch("/api/v1/metrics")
      .then(function (r) { return r.json(); })
      .then(function (data) {
        document.getElementById("m-cpu").innerText        = data.cpu;
        document.getElementById("m-lat").innerText        = data.latency;
        document.getElementById("m-throughput").innerText = data.throughput;
        if (data.flows_processed !== undefined)
          document.getElementById("m-flows").innerText   = data.flows_processed.toLocaleString();
        if (data.threats_detected !== undefined)
          document.getElementById("m-threats").innerText = data.threats_detected.toLocaleString();
        if (data.benign_flows !== undefined)
          document.getElementById("m-benign").innerText  = data.benign_flows.toLocaleString();
      })
      .catch(function () {});
  }

  // ── Forecast Fetch ────────────────────────────────────────────
  function fetchForecast() {
    if (!isEngineRunning) {
      document.getElementById("forecast-risk").innerText = "5.0%";
      document.getElementById("forecast-text").innerText = "Engine offline. Forecasting disabled.";
      document.getElementById("forecast-risk").style.color = "#708090";
      return;
    }
    fetch("/api/v1/forecast")
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var elRisk = document.getElementById("forecast-risk");
        elRisk.innerText = data.risk_score.toFixed(1) + "%";
        document.getElementById("forecast-text").innerText = data.prediction;
        
        if (data.risk_score > 70) {
            elRisk.style.color = "var(--magenta)";
            elRisk.style.textShadow = "var(--glow-red)";
        } else if (data.risk_score > 30) {
            elRisk.style.color = "#ff8c00";
            elRisk.style.textShadow = "0 0 15px rgba(255,140,0,0.4)";
        } else {
            elRisk.style.color = "var(--cyan)";
            elRisk.style.textShadow = "var(--glow-cyan)";
        }
      })
      .catch(function(){});
  }

  // ── Packets Fetch ────────────────────────────────────────
  function fetchPackets() {
    if (!isEngineRunning) return;
    fetch("/api/v1/packets")
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data.packets || data.packets.length === 0) return;
        data.packets.forEach(function (pkt) {
          var p = document.createElement("div");
          p.className = "packet-line";
          p.innerHTML =
            "> <span class='ip'>" + pkt.src_ip + "</span>" +
            " \u2192 <span class='ip'>" + pkt.dst_ip + "</span>" +
            " [<span class='proto'>" + pkt.protocol + "</span>]" +
            " len: <span class='len'>" + pkt.length + "</span>";
          packetLog.prepend(p);
          if (packetLog.children.length > 15) {
            packetLog.removeChild(packetLog.lastChild);
          }
        });
      })
      .catch(function () {});
  }

  // ── Simulator ─────────────────────────────────────────────
  window.launchSimAttack = function(type) {
    if (!isEngineRunning) {
      showToast("Start Engine first!");
      return;
    }
    fetch('/api/v1/simulate/' + type, {method: 'POST'})
      .then(function(r) { return r.json(); })
      .then(function(data) {
        showToast(data.message || "Simulated attack launched!");
      })
      .catch(function(e) { showToast("Simulation error"); });
  };

  // ── Init ─────────────────────────────────────────────────
  fetchStatus();
  setInterval(fetchStatus,  2000);
  setInterval(fetchAlerts,  1000);
  setInterval(fetchMetrics, 1500);
  setInterval(fetchForecast, 2000);
  setInterval(fetchPackets,  500);

  console.log("[THREAT VISION] Dashboard JS loaded. API polling active.");
})();
