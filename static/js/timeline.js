(function(){
  async function render() {
    const container = document.getElementById('timeline');
    try {
      const caseId = (typeof CASE_ID !== 'undefined' && CASE_ID) ? CASE_ID : null;
      const url = caseId ? `/api/timeline/${caseId}` : '/api/timeline';
      console.debug("Fetching timeline from", url);

      const resp = await fetch(url);
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const payload = await resp.json();
      console.debug("Timeline payload", payload);

      // Support { timeline: [...] } or direct array
      const list = payload.timeline || payload.events || payload || [];
      container.innerHTML = '';

      if (!list.length) {
        container.textContent = 'No events found.';
        return;
      }

      for (const ev of list) {
        const el = document.createElement('div'); el.className = 'event';
        const ts = document.createElement('div'); ts.className = 'ts';
        ts.textContent = ev.timestamp || '(no timestamp)';
        const meta = document.createElement('div'); meta.className = 'meta';
        meta.textContent = `${ev.source || ''} — ${ev.type || 'event'}`;
        const pre = document.createElement('pre');
        try { pre.textContent = JSON.stringify(ev, null, 2); }
        catch(e) { pre.textContent = String(ev); }
        el.appendChild(ts); el.appendChild(meta); el.appendChild(pre);
        container.appendChild(el);
      }
    } catch (err) {
      container.textContent = 'Failed to load timeline: ' + err;
      console.error(err);
    }
  }
  document.addEventListener('DOMContentLoaded', render);
})();
