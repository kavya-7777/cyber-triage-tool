// static/js/artifacts_loader.js
window.ArtifactsLoader = (function(){
  async function fetchCounts(caseId){
    try {
      const resp = await fetch(`/api/case/${encodeURIComponent(caseId)}/counts`);
      if (!resp.ok) return null;
      return await resp.json();
    } catch (e) {
      console.error("counts fetch failed", e);
      return null;
    }
  }

  function renderBadge(container, counts){
    if (!container) return;
    const art = counts ? counts.artifact_count : '?';
    const tl = counts ? counts.timeline_count : '?';
    container.innerHTML = `<small class="text-muted">Timeline (${tl}) — Artifacts (${art})</small>`;
    if (counts && counts.timeline_count !== counts.artifact_count){
      const warn = document.createElement('span');
      warn.className = 'badge bg-warning text-dark ms-2';
      warn.textContent = 'Unsynced';
      container.appendChild(warn);
    }
  }

  async function init(caseId){
    if (!caseId) return;
    const container = document.getElementById('timeline-artifact-badge');
    const counts = await fetchCounts(caseId);
    renderBadge(container, counts);
  }

  return { init };
})();
