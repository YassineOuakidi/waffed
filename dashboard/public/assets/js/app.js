(() => {
    const logTail = document.getElementById('log-tail');
    const logStatus = document.getElementById('log-status');
    const logMeta = document.getElementById('log-meta');
    const autoRefresh = document.getElementById('auto-refresh');
    const autoScroll = document.getElementById('auto-scroll');
    const manualRefresh = document.getElementById('manual-log-refresh');
    const clearView = document.getElementById('clear-view');
    const reloadPage = document.getElementById('reload-page');
    const ruleSearch = document.getElementById('rule-search');

    let timer = null;
    let lastPayload = '';

    function setText(id, value) {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    }

    function setStatus(message, className = 'live') {
        if (!logStatus) return;
        logStatus.textContent = message;
        logStatus.className = className;
    }

    function ajaxUrl() {
        if (logTail?.dataset.ajaxUrl) {
            return logTail.dataset.ajaxUrl + '&_=' + Date.now();
        }
        const base = window.location.pathname || '/';
        return base + '?ajax=logs&_=' + Date.now();
    }

    async function refreshLogs(manual = false) {
        if (!logTail) return;

        if (manual) setStatus('Refreshing...', 'live');

        try {
            const response = await fetch(ajaxUrl(), {
                method: 'GET',
                cache: 'no-store',
                headers: { 'Accept': 'application/json' },
            });

            if (!response.ok) {
                throw new Error('HTTP ' + response.status);
            }

            const data = await response.json();
            const lines = Array.isArray(data.lines) ? data.lines : [];
            const payload = lines.join('\n');

            if (payload !== lastPayload) {
                logTail.textContent = payload || '[empty log window]';
                lastPayload = payload;
                if (!autoScroll || autoScroll.checked) {
                    logTail.scrollTop = logTail.scrollHeight;
                }
            }

            const summary = data.summary || {};
            setText('metric-events', summary.events ?? lines.length);
            setText('metric-drops', summary.drops ?? 0);
            setText('metric-sqli', summary.sqli ?? 0);
            setText('metric-xss', summary.xss ?? 0);
            setText('metric-ac', summary.ac ?? 0);
            setText('metric-reason', summary.last_reason ?? 'none');

            const readable = data.readable ? 'readable' : 'not readable';
            if (logMeta) {
                logMeta.textContent = `${readable} · ${data.size || '0 B'} · file mtime ${data.mtime || 'n/a'} · refreshed ${data.server_time || ''}`;
            }
            setStatus('Live refresh OK', 'live');
        } catch (err) {
            setStatus('Refresh failed: ' + err.message, 'error');
        }
    }

    function startTimer() {
        if (timer) clearInterval(timer);
        timer = setInterval(() => {
            if (!autoRefresh || autoRefresh.checked) {
                refreshLogs(false);
            }
        }, 2000);
    }

    if (manualRefresh) {
        manualRefresh.addEventListener('click', () => refreshLogs(true));
    }

    if (clearView && logTail) {
        clearView.addEventListener('click', () => {
            logTail.textContent = '';
            lastPayload = '';
            setStatus('View cleared; next refresh will repopulate it', 'live');
        });
    }

    if (reloadPage) {
        reloadPage.addEventListener('click', () => {
            window.location.reload();
        });
    }

    if (ruleSearch) {
        ruleSearch.addEventListener('input', () => {
            const q = ruleSearch.value.trim().toLowerCase();
            document.querySelectorAll('[data-rule-row]').forEach((row) => {
                row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
            });
        });
    }

    document.querySelectorAll('form').forEach((form) => {
        form.addEventListener('submit', () => {
            const button = form.querySelector('button[type="submit"]');
            if (button) {
                button.dataset.originalText = button.textContent;
                button.textContent = 'Saving...';
                button.disabled = true;
            }
        });
    });

    refreshLogs(true);
    startTimer();
})();
