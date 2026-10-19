/**
 * app.js - Shared Client-Side Logic for MedShield
 */

// Initialize UI on page load
document.addEventListener('DOMContentLoaded', async () => {
    await updateModeBadge();

    const toggleBtn = document.getElementById('toggle-mode-btn');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', async () => {
            try {
                const res = await fetch('/api/mode/toggle', { method: 'POST' });
                const data = await res.json();
                window.location.reload();
            } catch (err) {
                console.error('Failed to toggle mode:', err);
            }
        });
    }

    // Setup chip click-to-fill helpers
    document.querySelectorAll('.chip').forEach(chip => {
        chip.addEventListener('click', () => {
            const targetInputId = chip.getAttribute('data-target');
            const target = document.getElementById(targetInputId);
            if (target) {
                target.value = chip.getAttribute('data-payload');
                target.focus();
            }
        });
    });
});

async function updateModeBadge() {
    try {
        const res = await fetch('/api/mode');
        const data = await res.json();

        const badge = document.getElementById('nav-mode-badge');
        const toggleBtn = document.getElementById('toggle-mode-btn');

        if (badge) {
            if (data.isSafeMode) {
                badge.className = 'mode-badge safe';
                badge.innerHTML = '🟢 SAFE (HARDENED) MODE';
                if (toggleBtn) toggleBtn.textContent = 'Switch to Vulnerable';
            } else {
                badge.className = 'mode-badge vulnerable';
                badge.innerHTML = '🔴 VULNERABLE MODE';
                if (toggleBtn) toggleBtn.textContent = 'Switch to Safe Mode';
            }
        }
    } catch (e) {
        console.warn('Could not contact API for mode status:', e);
    }
}
