// static/js/artifacts_loader.js
// Corrected & robust CoC + Verify wiring (fixes attribute mismatches + fallback behaviors)

"use strict";

// ------- safe-response helpers -------
async function safeFetchJson(resp) {
  try {
    return await resp.json();
  } catch (err) {
    try {
      const clone = resp.clone();
      const txt = await clone.text();
      return JSON.parse(txt);
    } catch (err2) {
      try {
        const txt2 = await resp.text();
        return JSON.parse(txt2);
      } catch (err3) {
        const e = new Error("safeFetchJson: unable to parse response body as JSON");
        e.originalErrors = [err, err2, err3];
        throw e;
      }
    }
  }
}

async function fetchJsonWrapped(url, opts) {
  const resp = await fetch(url, opts);
  let data = null;
  try {
    data = await safeFetchJson(resp);
  } catch (e) {
    return { ok: resp.ok, status: resp.status, data: null, parse_error: String(e) };
  }
  return { ok: resp.ok, status: resp.status, data: data };
}
// ------- end helpers -------


// Robust upload helper you can wire to your upload form
async function robustUploadFormSubmit(formEl) {
  const formData = new FormData(formEl);
  try {
    const respWrapper = await fetchJsonWrapped(formEl.action || '/upload', {
      method: 'POST',
      body: formData
    });

    if (!respWrapper.ok) {
      const payload = respWrapper.data;
      console.debug('Upload failed status', respWrapper.status, payload, respWrapper.parse_error);
      const errMsg = (payload && payload.error) ? payload.error : 'Upload failed';
      alert('Upload failed: ' + errMsg);
      return { ok: false, error: errMsg, payload: payload };
    }

    const payload = respWrapper.data;
    console.debug('Upload success payload', payload);

    if (window.ArtifactsLoader && typeof window.ArtifactsLoader.onUploadSuccess === 'function') {
      try { window.ArtifactsLoader.onUploadSuccess(payload); } catch (e) { console.error(e); }
    }

    return { ok: true, payload: payload };

  } catch (e) {
    console.error('robustUploadFormSubmit caught', e);
    alert('Upload failed (client error). See console for details.');
    return { ok: false, error: String(e) };
  }
}


// ArtifactsLoader small module (keeps previous functionality)
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

  // Expose the upload helper in the loader for convenience
  return { init, robustUploadFormSubmit };
})();


// -----------------------------
// Modal & Why? helper script
// -----------------------------
(function(){
  // small utilities
  function escTextNode(parent, text) {
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

    var whyScoreEl = document.getElementById('why-score');
    var whyBadgeEl = document.getElementById('why-badge');
    var whyArtifactEl = document.getElementById('why-artifact-id');
    var breakdownNode = document.getElementById('why-breakdown');
    var detailsNode = document.getElementById('why-details');
    var reasonsNode = document.getElementById('why-reasons');
    var copyBtn = document.getElementById('copyWhyBtn');

    if (!whyScoreEl || !whyBadgeEl || !whyArtifactEl || !breakdownNode || !detailsNode || !reasonsNode) {
      console.debug("Why modal elements not present; skipping modal population");
      return;
    }

    var fs = analysis.final_score || analysis.suspicion_score || 0;
    escTextNode(whyScoreEl, fs);
    whyBadgeEl.innerHTML = formatBadge(Number(fs) || 0);
    escTextNode(whyArtifactEl, analysis.artifact_id || '');

    breakdownNode.innerHTML = '';
    var comps = analysis.components || analysis.breakdown || {};
    var iocv = (comps.ioc && comps.ioc.score) || comps.ioc_component || comps.ioc || 0;
    var yarav = (comps.yara && comps.yara.score) || comps.yara_component || comps.yara || 0;
    var heurv = (comps.heuristics && comps.heuristics.score) || comps.heuristics_component || comps.heuristics || 0;
    var repv = (comps.reputation && comps.reputation.score) || comps.reputation_component || comps.reputation || 0;
    iocv = parseInt(iocv) || 0; yarav = parseInt(yarav) || 0; heurv = parseInt(heurv) || 0; repv = parseInt(repv) || 0;

    breakdownNode.innerHTML += renderComponentRow('IOC', iocv);
    breakdownNode.innerHTML += renderComponentRow('YARA', yarav);
    breakdownNode.innerHTML += renderComponentRow('Heuristics', heurv);
    breakdownNode.innerHTML += renderComponentRow('Reputation', repv);

    detailsNode.innerHTML = '';
    var compDetails = analysis.components_details || analysis.components || {};
    var iocMatchesList = (compDetails.ioc && compDetails.ioc.matches) ? compDetails.ioc.matches : (analysis.ioc_matches || []);
    var yaraMatchesList = (compDetails.yara && compDetails.yara.matches) ? compDetails.yara.matches : (analysis.yara_matches || []);
    var heurList = (compDetails.heuristics && compDetails.heuristics.reasons) ? compDetails.heuristics.reasons :
                   ((analysis.components && analysis.components.heuristics && analysis.components.heuristics.reasons) ? analysis.components.heuristics.reasons : (analysis.reasons || []));
    var repList = (compDetails.reputation && compDetails.reputation.reasons) ? compDetails.reputation.reasons : (analysis.reputation && analysis.reputation.reasons ? analysis.reputation.reasons : []);

    detailsNode.innerHTML += renderDetailsList('IOC matches', iocMatchesList);
    detailsNode.innerHTML += renderDetailsList('YARA matches', yaraMatchesList);
    detailsNode.innerHTML += renderDetailsList('Heuristics', heurList);
    detailsNode.innerHTML += renderDetailsList('Reputation notes', repList);

    reasonsNode.innerHTML = '';
    var reasons = analysis.reasons || analysis.final_reasons || [];
    reasons.forEach(function(r){
      var li = document.createElement('li');
      li.textContent = clampString(typeof r === 'string' ? r : JSON.stringify(r), 300);
      reasonsNode.appendChild(li);
    });

    if (copyBtn) {
      copyBtn.onclick = function(){
        copyToClipboard(JSON.stringify(analysis, null, 2)).then(function(){
          copyBtn.textContent = 'Copied!';
          setTimeout(function(){ copyBtn.textContent = 'Copy JSON'; }, 1200);
        });
      };
    }

    setTimeout(function(){
      var bars = breakdownNode.querySelectorAll('.progress-bar');
      bars.forEach(function(b){
        if (!b.style.transition) b.style.transition = 'width 700ms ease';
      });
    }, 80);

        // --- show the Why? modal (ensure bootstrap is loaded) ---
    try {
      var modalEl = document.getElementById('whyModal');
      if (modalEl) {
        if (window.bootstrap && typeof bootstrap.Modal === 'function') {
          // get or create modal instance and show it
          var modalInstance = bootstrap.Modal.getOrCreateInstance(modalEl);
          modalInstance.show();
        } else {
          // bootstrap not available yet — log a helpful message
          console.warn("Bootstrap Modal API not available; ensure bootstrap.bundle.js is loaded before artifact_loader.js");
        }
      } else {
        console.debug("whyModal element not found in DOM; cannot open modal");
      }
    } catch (e) {
      console.debug("Failed to show why modal", e);
    }


  }, 200)); // debounce 200ms

})();


// animate progress bars that have a data-width attribute
document.addEventListener('DOMContentLoaded', function(){
  setTimeout(function(){
    document.querySelectorAll('.progress-bar[data-width]').forEach(function(bar){
      try {
        var target = parseInt(bar.getAttribute('data-width')) || 0;
        if (!bar.style.transition) bar.style.transition = 'width 700ms ease';
        bar.style.width = target + '%';
      } catch(e){
        console.debug("progress-bar animate error", e);
      }
    });
  }, 80);
});


// -----------------------------
// Verify & CoC UI wiring
// -----------------------------
document.addEventListener('DOMContentLoaded', function () {
  // init bootstrap tooltips if available
  try {
    var tList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tList.forEach(function(el) { new bootstrap.Tooltip(el); });
  } catch (e) {}

  // Helper: current case id
  function currentCaseId() {
    return (new URLSearchParams(window.location.search)).get('case_id') || document.querySelector('select[name="case_id"]')?.value || 'case001';
  }

  // VERIFY button: call /api/coc/verify/<case>/<artifact> and update a visible element
  document.querySelectorAll('.verify-btn').forEach(function(btn) {
    btn.addEventListener('click', async function(ev) {
      // prefer data-art, fallback to data-artifact
      var art = btn.getAttribute('data-art') || btn.getAttribute('data-artifact');
      if (!art) return;
      // prefer verify-result-<id> (dashboard change). fallback to meta-status-<id>
      var statusEl = document.getElementById('verify-result-' + art) || document.getElementById('meta-status-' + art);
      if (!statusEl) {
        // if no element adjacent, try to find a sibling element in same row
        var row = btn.closest('tr');
        if (row) {
          statusEl = row.querySelector('#verify-result-' + art) || row.querySelector('#meta-status-' + art) || row.querySelector('.meta-status') || null;
        }
      }
      if (!statusEl) return;
      statusEl.innerHTML = '<span class="badge bg-secondary">Verifying…</span>';
      try {
        var caseId = currentCaseId();
        var resp = await fetch('/api/coc/verify/' + encodeURIComponent(caseId) + '/' + encodeURIComponent(art));
        var data = null;
        try { data = await safeFetchJson(resp); } catch (e) { console.error("parse error", e); }

        if (!resp.ok) {
          statusEl.innerHTML = '<span class="badge bg-danger">Verify error</span>';
          return;
        }

        // show metadata HMAC state
        if (data && data.metadata_hmac_ok) {
          if (data.on_disk_sha256 && data.computed_sha256 && data.on_disk_sha256 === data.computed_sha256) {
            statusEl.innerHTML = '<span class="badge bg-success">OK ✔</span>';
            statusEl.title = `sha256: ${data.computed_sha256 || ''}`;
          } else if (data.on_disk_sha256 && data.computed_sha256 && data.on_disk_sha256 !== data.computed_sha256) {
            statusEl.innerHTML = '<span class="badge bg-danger">HASH MISMATCH ✖</span><div class="small text-muted">expected:' + (data.on_disk_sha256?data.on_disk_sha256.slice(0,8)+'…':'?') + ' got ' + (data.computed_sha256?data.computed_sha256.slice(0,8)+'…':'?') + '</div>';
          } else {
            statusEl.innerHTML = '<span class="badge bg-success">META OK</span>';
            if (data.on_disk_sha256) statusEl.title = `manifest sha: ${data.on_disk_sha256}`;
          }
        } else {
          statusEl.innerHTML = '<span class="badge bg-danger">META TAMPERED ✖</span>';
          if (data && data.metadata_hmac_details) {
            var det = data.metadata_hmac_details;
            if (det.expected || det.observed) {
              statusEl.innerHTML += '<div class="small text-muted">expected:'+ (det.expected ? det.expected.slice(0,8)+'…':'?') + ' observed:' + (det.observed ? det.observed.slice(0,8)+'…':'?') + '</div>';
            } else {
              statusEl.title = JSON.stringify(det || {});
            }
          }
        }
      } catch (e) {
        statusEl.innerHTML = '<span class="badge bg-danger">Verify failed</span>';
        console.error(e);
      }
    });
  });


  // CoC per-artifact: open modal and load entries from /api/coc/<case>/<artifact>
  async function loadCocForArtifact(caseId, artifactId) {
    var entriesEl = document.getElementById('coc-entries');
    var loading = document.getElementById('coc-loading');
    if (!entriesEl) return;
    entriesEl.innerHTML = '';
    if (loading) loading.textContent = 'Loading CoC entries…';
    try {
      var resp = await fetch('/api/coc/' + encodeURIComponent(caseId) + '/' + encodeURIComponent(artifactId));
      if (!resp.ok) {
        entriesEl.innerHTML = '<div class="text-danger small">Failed to load CoC entries</div>';
        if (loading) loading.textContent = '';
        return;
      }
      var rows = await resp.json();
      if (!rows || rows.length === 0) {
        entriesEl.innerHTML = '<div class="small text-muted">No CoC entries for artifact ' + artifactId + '.</div>';
      } else {
        rows.sort(function(a,b){ return new Date(a.ts) - new Date(b.ts); });
        rows.forEach(function(r){
          var item = document.createElement('div');
          item.className = 'list-group-item';
          var details = '<div><strong>' + (r.actor||'unknown') + '</strong> — <small class="text-muted">' + (r.action||'') + ' @ ' + (r.ts || '') + '</small></div>';
          details += '<div class="small">' + (r.reason || '') + (r.location ? ' — ' + r.location : '') + '</div>';
          if (r.signature) details += '<div class="mt-1 small text-muted">sig: ' + r.signature.slice(0,12) + '…</div>';
          item.innerHTML = details;
          entriesEl.appendChild(item);
        });
      }
    } catch (e) {
      entriesEl.innerHTML = '<div class="text-danger small">Error loading CoC</div>';
      console.error(e);
    } finally {
      if (loading) loading.textContent = '';
    }
  }

  document.querySelectorAll('.coc-btn').forEach(function(btn) {
    btn.addEventListener('click', function(){
      var art = btn.getAttribute('data-art') || btn.getAttribute('data-artifact');
      if (!art) return;
      var caseIdInput = (new URLSearchParams(window.location.search)).get('case_id') || document.querySelector('select[name="case_id"]')?.value || 'case001';
      var modalEl = document.getElementById('cocModal');
      if (!modalEl) {
        // fallback: try to open bootstrap modal by id; if not present just open a plain dialog
        console.debug('cocModal not found in DOM');
      } else {
        var modal = new bootstrap.Modal(modalEl);
        modal.show();
      }
      var label = document.getElementById('cocModalLabel');
      if (label) label.textContent = 'Chain of Custody — Artifact: ' + art;
      loadCocForArtifact(caseIdInput, art);

      (async function(){
        try {
          var resp = await fetch('/api/coc/' + encodeURIComponent(caseIdInput) + '/' + encodeURIComponent(art));
          if (resp.ok) {
            var rows = await resp.json();
            var summ = rows && rows.length ? (rows.length + ' entry' + (rows.length>1 ? 'ies' : '')) : 'No CoC entries';
            var el = document.getElementById('coc-summary-' + art);
            if (el) el.textContent = summ;
          }
        } catch(e){}
      })();
    });
  });

  // Case-level CoC aggregation: gather CoC entries for all artifacts shown
  document.getElementById('case-coc-btn')?.addEventListener('click', async function(){
    var caseId = (new URLSearchParams(window.location.search)).get('case_id') || document.querySelector('select[name="case_id"]')?.value || 'case001';
    var modalEl = document.getElementById('cocModal');
    if (modalEl) new bootstrap.Modal(modalEl).show();
    var label = document.getElementById('cocModalLabel');
    if (label) label.textContent = 'Chain of Custody — Case: ' + caseId;
    var entriesEl = document.getElementById('coc-entries');
    var loading = document.getElementById('coc-loading');
    if (!entriesEl) return;
    entriesEl.innerHTML = '';
    if (loading) loading.textContent = 'Gathering CoC entries for case…';

    // find artifact ids from rows:
    var rows = Array.from(document.querySelectorAll('tr[id^="row-"], tr[data-artifact-id]'));
    var artifactIds = rows.map(function(r){
      if (r.getAttribute('data-artifact-id')) return r.getAttribute('data-artifact-id');
      var id = r.id || '';
      if (id && id.indexOf('row-') === 0) return id.replace(/^row-/, '');
      return null;
    }).filter(Boolean);

    var combined = [];
    for (var i=0;i<artifactIds.length;i++) {
      var art = artifactIds[i];
      try {
        var resp = await fetch('/api/coc/' + encodeURIComponent(caseId) + '/' + encodeURIComponent(art));
        if (resp.ok) {
          var arr = await resp.json();
          arr.forEach(function(item){ item._artifact_id = art; combined.push(item); });
        }
      } catch(e) {
        console.debug('CoC fetch failed for', art, e);
      }
    }

    if (combined.length === 0) {
      entriesEl.innerHTML = '<div class="small text-muted">No CoC entries found for case.</div>';
      if (loading) loading.textContent = '';
      return;
    }

    combined.sort(function(a,b){ return new Date(a.ts) - new Date(b.ts); });
    combined.forEach(function(r){
      var el = document.createElement('div');
      el.className = 'list-group-item';
      var header = '<div><strong>' + (r.actor||'unknown') + '</strong> — <small class="text-muted">' + (r.action||'') + ' @ ' + (r.ts||'') + '</small></div>';
      var artifactLbl = '<div class="small text-muted">artifact: <code>' + (r._artifact_id || '') + '</code></div>';
      var reason = '<div class="small">' + (r.reason || '') + (r.location ? ' — ' + r.location : '') + '</div>';
      if (r.signature) reason += '<div class="mt-1 small text-muted">sig: ' + r.signature.slice(0,12) + '…</div>';
      el.innerHTML = header + artifactLbl + reason;
      entriesEl.appendChild(el);
    });

    if (loading) loading.textContent = '';
  });

  // Coc modal refresh button logic
  document.getElementById('coc-refresh-btn')?.addEventListener('click', function(){
    var title = document.getElementById('cocModalLabel')?.textContent || '';
    if (title.indexOf('Artifact:') !== -1) {
      var art = title.split('Artifact:').pop().trim();
      var caseId = (new URLSearchParams(window.location.search)).get('case_id') || document.querySelector('select[name="case_id"]')?.value || 'case001';
      loadCocForArtifact(caseId, art);
    } else {
      document.getElementById('case-coc-btn')?.click();
    }
  });

  // Implement the missing refreshCocSummaryForArtifact used after CoC add
  window.refreshCocSummaryForArtifact = async function(caseId, artifactId) {
    try {
      var resp = await fetch('/api/coc/' + encodeURIComponent(caseId) + '/' + encodeURIComponent(artifactId));
      if (!resp.ok) return;
      var rows = await resp.json();
      var summ = rows && rows.length ? (rows.length + ' entry' + (rows.length>1 ? 'ies' : '')) : 'No CoC entries';
      var el = document.getElementById('coc-summary-' + artifactId);
      if (el) el.textContent = summ;
    } catch (e) {
      console.debug('refreshCocSummaryForArtifact failed', e);
    }
  };

}); // DOMContentLoaded end