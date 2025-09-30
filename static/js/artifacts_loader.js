// static/js/artifacts_loader.js
// Enhanced artifacts loader + "Why?" modal support
// Improvements: safer JSON parsing, defensive DOM checks, truncation of long texts,
// progress bar animation on modal open, debounce on clicks.
//
// Replace the existing file with this content.

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

// -----------------------------
// Modal & Why? helper script
// -----------------------------
(function(){
  // small utilities
  function escTextNode(parent, text) {
    // insert text safely rather than setting innerHTML
    if (!parent) return;
    parent.textContent = (text === null || text === undefined) ? '' : String(text);
  }

  function clampString(s, maxLen) {
    if (typeof s !== 'string') return s;
    if (s.length <= maxLen) return s;
    return s.slice(0, maxLen) + '…';
  }

  function formatBadge(score) {
    var cls = "badge bg-success";
    if (score >= 70) cls = "badge bg-danger";
    else if (score > 30) cls = "badge bg-warning text-dark";
    return '<span class="' + cls + '">' + score + '%</span>';
  }

  function createProgressBar(score) {
    var color = "bg-success";
    if (score >= 70) color = "bg-danger";
    else if (score > 30) color = "bg-warning";
    var tpl = '<div class="progress" style="height:10px;"><div class="progress-bar ' + color + '" role="progressbar" style="width:' + score + '%" aria-valuenow="' + score + '" aria-valuemin="0" aria-valuemax="100"></div></div>';
    return tpl;
  }

  function renderComponentRow(name, value) {
    value = parseInt(value) || 0;
    return '<div class="mb-2"><strong>' + name + '</strong><div class="mt-1">' + createProgressBar(value) +
           '<div class="small text-muted mt-1">' + value + '/100</div></div></div>';
  }

  function renderDetailsList(title, items) {
    if(!items || items.length === 0) return '';
    var out = '<div class="mb-2"><details><summary><strong>' + title + ' (' + items.length + ')</strong></summary><div class="mt-2"><ul class="small">';
    items.forEach(function(it){
      // it may be dict-like or string
      if (typeof it === 'string') {
        out += '<li>' + escapeHtml(clampString(it, 300)) + '</li>';
      } else if (it && typeof it === 'object') {
        var v = it.value || it.match || it.rule || JSON.stringify(it);
        out += '<li><code>' + escapeHtml(clampString(String(v), 200)) + '</code>';
        if (it.points) out += ' <span class="text-success">(+ ' + escapeHtml(String(it.points)) + ')</span>';
        if (it.confidence) out += ' <span class="text-muted">[' + escapeHtml(String(it.confidence)) + ']</span>';
        out += '</li>';
      } else {
        out += '<li>' + escapeHtml(String(it)) + '</li>';
      }
    });
    out += '</ul></div></details></div>';
    return out;
  }

  function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // copy to clipboard helper
  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    // fallback
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = 0;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch(e){}
    document.body.removeChild(ta);
    return Promise.resolve();
  }

  // small debounce to prevent double-handling
  var clickLock = false;
  function withDebounce(fn, delay){
    return function(ev){
      if (clickLock) return;
      clickLock = true;
      try { fn(ev); } finally {
        setTimeout(function(){ clickLock = false; }, delay || 300);
      }
    };
  }

  // When a Why? button is clicked, populate modal
  document.addEventListener('click', withDebounce(function(ev){
    var t = ev.target;
    // support clicks on child elements of the button
    var btn = t.closest ? t.closest('.why-btn') : null;
    if (!btn) return;
    var raw = btn.getAttribute('data-analysis');
    if (!raw) return;
    var analysis;
    try {
      analysis = JSON.parse(raw);
    } catch(e) {
      console.warn("artifacts_loader: failed parsing analysis JSON for artifact", e);
      return;
    }

    // locate modal elements defensively
    var whyScoreEl = document.getElementById('why-score');
    var whyBadgeEl = document.getElementById('why-badge');
    var whyArtifactEl = document.getElementById('why-artifact-id');
    var breakdownNode = document.getElementById('why-breakdown');
    var detailsNode = document.getElementById('why-details');
    var reasonsNode = document.getElementById('why-reasons');
    var copyBtn = document.getElementById('copyWhyBtn');

    if (!whyScoreEl || !whyBadgeEl || !whyArtifactEl || !breakdownNode || !detailsNode || !reasonsNode) {
      // If the modal isn't on the page, quietly return (helps tests)
      console.debug("Why modal elements not present; skipping modal population");
      return;
    }

    // header
    var fs = analysis.final_score || analysis.suspicion_score || 0;
    escTextNode(whyScoreEl, fs);
    whyBadgeEl.innerHTML = formatBadge(Number(fs) || 0);
    escTextNode(whyArtifactEl, analysis.artifact_id || '');

    // breakdown area
    breakdownNode.innerHTML = '';
    var comps = analysis.components || analysis.breakdown || {};
    // Normalized keys may be nested; try to extract numeric scores
    var iocv = (comps.ioc && comps.ioc.score) || comps.ioc_component || comps.ioc || 0;
    var yarav = (comps.yara && comps.yara.score) || comps.yara_component || comps.yara || 0;
    var heurv = (comps.heuristics && comps.heuristics.score) || comps.heuristics_component || comps.heuristics || 0;
    var repv = (comps.reputation && comps.reputation.score) || comps.reputation_component || comps.reputation || 0;
    // coerce to int
    iocv = parseInt(iocv) || 0; yarav = parseInt(yarav) || 0; heurv = parseInt(heurv) || 0; repv = parseInt(repv) || 0;

    breakdownNode.innerHTML += renderComponentRow('IOC', iocv);
    breakdownNode.innerHTML += renderComponentRow('YARA', yarav);
    breakdownNode.innerHTML += renderComponentRow('Heuristics', heurv);
    breakdownNode.innerHTML += renderComponentRow('Reputation', repv);

    // details
    detailsNode.innerHTML = '';
    var compDetails = analysis.components_details || analysis.components || {};
    var iocMatchesList = (compDetails.ioc && compDetails.ioc.matches) ? compDetails.ioc.matches : (analysis.ioc_matches || []);
    var yaraMatchesList = (compDetails.yara && compDetails.yara.matches) ? compDetails.yara.matches : (analysis.yara_matches || []);
    var heurList = (compDetails.heuristics && compDetails.heuristics.reasons) ? compDetails.heuristics.reasons : 
                   ( (analysis.components && analysis.components.heuristics && analysis.components.heuristics.reasons) ? analysis.components.heuristics.reasons : (analysis.reasons || []) );
    var repList = (compDetails.reputation && compDetails.reputation.reasons) ? compDetails.reputation.reasons : (analysis.reputation && analysis.reputation.reasons ? analysis.reputation.reasons : []);

    detailsNode.innerHTML += renderDetailsList('IOC matches', iocMatchesList);
    detailsNode.innerHTML += renderDetailsList('YARA matches', yaraMatchesList);
    detailsNode.innerHTML += renderDetailsList('Heuristics', heurList);
    detailsNode.innerHTML += renderDetailsList('Reputation notes', repList);

    // summary reasons (text nodes to avoid HTML injection)
    reasonsNode.innerHTML = '';
    var reasons = analysis.reasons || analysis.final_reasons || [];
    reasons.forEach(function(r){
      var li = document.createElement('li');
      li.textContent = clampString(typeof r === 'string' ? r : JSON.stringify(r), 300);
      reasonsNode.appendChild(li);
    });

    // set JSON copy button payload
    if (copyBtn) {
      copyBtn.onclick = function(){
        copyToClipboard(JSON.stringify(analysis, null, 2)).then(function(){
          copyBtn.textContent = 'Copied!';
          setTimeout(function(){ copyBtn.textContent = 'Copy JSON'; }, 1200);
        });
      };
    }

    // Animate progress bars (in case modal just opened)
    // We give a small timeout to let the modal render (if using bootstrap modal open)
    setTimeout(function(){
      var bars = breakdownNode.querySelectorAll('.progress-bar');
      bars.forEach(function(b){
        // ensure style.width already set (createProgressBar sets it) — this is gentle.
        // Add CSS transition if not present
        if (!b.style.transition) b.style.transition = 'width 700ms ease';
      });
    }, 80);

  }, 200)); // debounce 200ms

})();

// animate all progress bars that have a data-width attribute
document.addEventListener('DOMContentLoaded', function(){
  setTimeout(function(){
    document.querySelectorAll('.progress-bar[data-width]').forEach(function(bar){
      try {
        var target = parseInt(bar.getAttribute('data-width')) || 0;
        // ensure transition exists
        if (!bar.style.transition) bar.style.transition = 'width 700ms ease';
        // trigger the animated width change
        bar.style.width = target + '%';
      } catch(e){
        console.debug("progress-bar animate error", e);
      }
    });
  }, 80); // tiny delay to allow any bootstrap modal display
});
