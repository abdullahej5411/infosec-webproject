/**
 * app.js - MedShield Client-Side Controller
 * Handles global security mode state, toggle interactions, and payload autofill.
 */

document.addEventListener('DOMContentLoaded', async () => {
    await updateModeBadge();

    const toggleBtn = document.getElementById('toggle-mode-btn');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', async () => {
            try {
                await fetch('/api/mode/toggle', { method: 'POST' });
                window.location.reload();
            } catch (err) {
                console.error('Failed to toggle mode:', err);
            }
        });
    }

    // Attach click-to-autofill listeners for chips
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
                badge.className = 'mode-indicator safe';
                badge.innerHTML = '<span class="status-dot"></span> SAFE';
                if (toggleBtn) toggleBtn.textContent = 'Toggle Mode';
            } else {
                badge.className = 'mode-indicator vulnerable';
                badge.innerHTML = '<span class="status-dot"></span> VULNERABLE';
                if (toggleBtn) toggleBtn.textContent = 'Toggle Mode';
            }
        }
    } catch (e) {
        console.warn('Could not contact API for mode status:', e);
    }
}
