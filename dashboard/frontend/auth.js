// auth.js - Role-based access control and session management

(function() {
    const token = localStorage.getItem('threat_token');
    if (!token) {
        window.location.href = '/login.html';
        return;
    }

    const role = localStorage.getItem('threat_role') || 'viewer';
    const user = localStorage.getItem('threat_user') || 'UNKNOWN';

    // Wait for DOM to load
    document.addEventListener('DOMContentLoaded', () => {
        // Apply role restrictions
        applyRoleRestrictions(role);
        
        // Inject user profile UI
        injectUserProfile(user, role);
    });

    function applyRoleRestrictions(role) {
        // Common elements
        const engineBtn = document.getElementById('btn-toggle-engine');
        const settingsNav = document.querySelector('a[href="settings.html"]');
        const neuralCoreNav = document.querySelector('a[href="neural_core.html"]');
        const networkMapNav = document.querySelector('a[href="network_map.html"]');
        const firewallNav = document.querySelector('a[href="firewall.html"]');
        
        const packetMonitor = document.querySelector('.packet-monitor');
        const llmPanel = document.querySelector('.llm-panel');
        const metricsGrid = document.querySelector('.metrics-grid');
        
        // Viewer restrictions (Executive / High-Level)
        if (role === 'viewer') {
            if (engineBtn) {
                engineBtn.style.display = 'none'; // Completely remove control
            }
            if (settingsNav) settingsNav.style.display = 'none';
            if (neuralCoreNav) neuralCoreNav.style.display = 'none'; // Too complex for viewer
            if (networkMapNav) networkMapNav.style.display = 'none';
            if (firewallNav) firewallNav.style.display = 'none'; // No firewall access
            
            if (packetMonitor) packetMonitor.style.display = 'none'; // Hide raw packets
            if (llmPanel) llmPanel.style.display = 'none'; // Hide LLM
            if (metricsGrid) {
                // Adjust grid layout since LLM is gone
                metricsGrid.style.gridTemplateColumns = '1fr 1fr';
                document.querySelector('.ai-footer').style.gridTemplateColumns = '1fr';
            }
            
            // Change title for flavor
            const titleEl = document.querySelector('title');
            if (titleEl) titleEl.innerText = "THREAT VISION - Executive Summary";
            const logoEl = document.querySelector('.logo');
            if (logoEl) logoEl.innerHTML = '<div class="pulse-dot" id="status-dot"></div> EXECUTIVE <span>VIEW</span>';
        }
        
        // Analyst restrictions (Triage & Monitoring)
        else if (role === 'analyst') {
            if (engineBtn) {
                engineBtn.disabled = true;
                engineBtn.style.opacity = '0.5';
                engineBtn.style.cursor = 'not-allowed';
                engineBtn.title = 'Only Admins can control the engine';
            }
            if (settingsNav) settingsNav.style.display = 'none';
            if (neuralCoreNav) neuralCoreNav.style.display = 'none'; // Hide backend core metrics
            if (firewallNav) firewallNav.style.display = 'none'; // Analysts can view logs but not block IPs
            
            // Highlight logs and map
            const titleEl = document.querySelector('title');
            if (titleEl) titleEl.innerText = "THREAT VISION - Analyst Console";
            const logoEl = document.querySelector('.logo');
            if (logoEl) logoEl.innerHTML = '<div class="pulse-dot" id="status-dot"></div> ANALYST <span>CONSOLE</span>';
            
            // Make alerts panel more prominent if possible
            const alertsPanel = document.querySelector('.alerts-panel');
            if (alertsPanel) {
                alertsPanel.style.borderLeft = '4px solid var(--magenta)';
                alertsPanel.style.boxShadow = '0 0 30px rgba(255, 0, 60, 0.1)';
            }
        }
        
        // Admin (Full Access)
        else if (role === 'admin') {
            const titleEl = document.querySelector('title');
            if (titleEl) titleEl.innerText = "THREAT VISION - Command Center";
            const logoEl = document.querySelector('.logo');
            if (logoEl) logoEl.innerHTML = '<div class="pulse-dot" id="status-dot"></div> COMMAND <span>CENTER</span>';
        }
    }

    function injectUserProfile(user, role) {
        const header = document.querySelector('header');
        if (!header) return;

        const profileDiv = document.createElement('div');
        profileDiv.className = 'user-profile';
        profileDiv.style.display = 'flex';
        profileDiv.style.alignItems = 'center';
        profileDiv.style.gap = '15px';
        profileDiv.style.fontFamily = "'JetBrains Mono', monospace";
        profileDiv.style.fontSize = '0.8rem';
        
        let roleColor = 'var(--cyan)';
        if (role === 'admin') roleColor = 'var(--magenta)';
        if (role === 'analyst') roleColor = 'var(--green)';
        
        profileDiv.innerHTML = `
            <div style="text-align: right;">
                <div style="color: \${roleColor}; font-weight: bold; text-transform: uppercase; text-shadow: 0 0 10px \${roleColor};">\${user}</div>
                <div style="color: var(--text-dim); font-size: 0.65rem; text-transform: uppercase;">[CLEARANCE: \${role}]</div>
            </div>
            <button id="btn-logout" style="
                background: rgba(255,0,60,0.1); border: 1px solid var(--magenta);
                color: var(--magenta); padding: 5px 10px; border-radius: 4px;
                cursor: pointer; font-family: 'JetBrains Mono', monospace; font-size: 0.7rem;
                transition: all 0.3s;
            " onmouseover="this.style.background='rgba(255,0,60,0.3)';this.style.boxShadow='0 0 10px rgba(255,0,60,0.5)';" onmouseout="this.style.background='rgba(255,0,60,0.1)';this.style.boxShadow='none';">TERMINATE</button>
        `;
        
        header.appendChild(profileDiv);

        document.getElementById('btn-logout').addEventListener('click', () => {
            localStorage.removeItem('threat_token');
            localStorage.removeItem('threat_role');
            localStorage.removeItem('threat_user');
            window.location.href = '/login.html';
        });
    }
})();
