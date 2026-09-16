/* Shared elapsed/ETA formatting for Mail Janitor status lines. */
window.MJProgress = {
  formatDuration(seconds) {
    if (seconds == null || Number.isNaN(Number(seconds))) return '—';
    let s = Math.max(0, Math.round(Number(seconds)));
    if (s < 60) return s + 's';
    const m = Math.floor(s / 60);
    s = s % 60;
    if (m < 60) return m + 'm ' + String(s).padStart(2, '0') + 's';
    const h = Math.floor(m / 60);
    return h + 'h ' + String(m % 60).padStart(2, '0') + 'm';
  },
  etaLine(eta) {
    if (!eta) return '';
    return eta.summary || '';
  },
  /** Poll until state is done/error; calls onTick(status) each poll. */
  async pollUntil(url, { intervalMs = 1000, onTick, maxMs = 300000 } = {}) {
    const t0 = Date.now();
    let sawRunning = false;
    for (;;) {
      const res = await fetch(url);
      if (!res.ok) throw new Error(res.statusText);
      const s = await res.json();
      if (onTick) onTick(s);
      if (s.state === 'running') sawRunning = true;
      if (s.state === 'done' || s.state === 'error') return s;
      // Ignore stale idle before the job has been observed running.
      if (s.state === 'idle' && sawRunning) return s;
      if (Date.now() - t0 > maxMs) throw new Error('Timed out waiting for job');
      await new Promise(r => setTimeout(r, intervalMs));
    }
  },
  /** Client-side elapsed while a promise runs (no server ETA yet). */
  trackElapsed(el, label, promise) {
    const t0 = Date.now();
    const timer = setInterval(() => {
      const sec = (Date.now() - t0) / 1000;
      el.textContent = label + ' · elapsed ' + this.formatDuration(sec);
    }, 400);
    return promise.finally(() => clearInterval(timer));
  },
};
