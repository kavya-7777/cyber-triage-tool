// static/js/why_modal.js
(function(){
  "use strict";

  function safeParse(raw){
    if(!raw && raw !== 0) return null;
    if(typeof raw === 'object') return raw;
    try { return JSON.parse(raw); } catch(e){ return null; }
  }

  // helper selectors
  function q(sel, ctx){ return (ctx || document).querySelector(sel); }
  function qa(sel, ctx){ return Array.from((ctx || document).querySelectorAll(sel)); }

  // little DOM helpers
  function make(tag, cls, txt){ const e = document.createElement(tag || 'div'); if(cls) e.className = cls; if(txt !== undefined) e.textContent = txt; return e; }

  // animate numeric progress width
  function animateBar(barEl, value){
    if(!barEl) return;
    // ensure starts at 0
    barEl.style.width = '0%';
    setTimeout(function(){ barEl.style.width = Math.max(0, Math.min(100, parseInt(value)||0)) + '%'; }, 40);
    barEl.setAttribute('aria-valuenow', Math.max(0, Math.min(100, parseInt(value)||0)));
  }

  // Render the top horizontal weights bars (like the screenshot)
function renderWeightBars(weights){
  const wrap = make('div', '');
  wrap.style.display = 'flex';
  wrap.style.gap = '20px';
  wrap.style.alignItems = 'center';
  wrap.style.flexWrap = 'wrap';
  wrap.style.justifyContent = 'center';

  const comps = [
    {k:'ioc', label:'IOC'},
    {k:'yara', label:'YARA'},
    {k:'heuristics', label:'HEURISTICS'}
  ];

  comps.forEach(c => {
    const val = Math.round(((weights && typeof weights[c.k] !== 'undefined') ? weights[c.k] : 0) * 100);

    // wrapper
    const item = make('div', 'd-flex align-items-center');
    item.style.gap = '6px';

    // small circular SVG indicator
    const svgNS = "http://www.w3.org/2000/svg";
    const size = 24;
    const strokeWidth = 3;
    const radius = (size - strokeWidth) / 2;
    const circumference = 2 * Math.PI * radius;
    const circleColor = val >= 70 ? '#dc3545' : val > 30 ? '#ffc107' : '#28a745';

    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("width", size);
    svg.setAttribute("height", size);
    svg.style.transform = "rotate(-90deg)";

    const bg = document.createElementNS(svgNS, "circle");
    bg.setAttribute("cx", size/2);
    bg.setAttribute("cy", size/2);
    bg.setAttribute("r", radius);
    bg.setAttribute("stroke", "#e5e5e5");
    bg.setAttribute("stroke-width", strokeWidth);
    bg.setAttribute("fill", "none");
    svg.appendChild(bg);

    const fg = document.createElementNS(svgNS, "circle");
    fg.setAttribute("cx", size/2);
    fg.setAttribute("cy", size/2);
    fg.setAttribute("r", radius);
    fg.setAttribute("stroke", circleColor);
    fg.setAttribute("stroke-width", strokeWidth);
    fg.setAttribute("fill", "none");
    fg.setAttribute("stroke-dasharray", circumference);
    fg.setAttribute("stroke-dashoffset", circumference);
    fg.style.transition = "stroke-dashoffset 1s ease";
    svg.appendChild(fg);

    // animate the stroke
    setTimeout(() => {
      const offset = circumference - (val / 100) * circumference;
      fg.setAttribute("stroke-dashoffset", offset);
    }, 100);

    // label + number
    const label = make('div', 'small fw-semibold', `${c.label} ${val}%`);
    label.style.textTransform = 'uppercase';
    label.style.minWidth = '90px';

    item.appendChild(svg);
    item.appendChild(label);
    wrap.appendChild(item);
  });

  return wrap;
}

  // Render detailed component breakdown bars (IOC/YARA/Heuristics component score)
  function renderComponentBars(breakdown, weights){
    const wrapper = make('div', '');
    wrapper.style.marginTop = '6px';

    const rows = [
      {key:'ioc_component', label:'IOC'},
      {key:'yara_component', label:'YARA'},
      {key:'heuristics_component', label:'HEURISTICS'},
    
    ];

    rows.forEach(r => {
      const val = parseInt((breakdown && typeof breakdown[r.key] !== 'undefined') ? breakdown[r.key] : 0) || 0;
      const row = make('div', 'mb-2');
      const rowInner = make('div', 'd-flex align-items-center');

      const badge = make('div', '', '');
      badge.style.minWidth = '60px';
      badge.style.marginRight = '8px';
      badge.innerHTML = `<strong>${r.label}</strong>`;

      const progWrap = make('div', 'flex-fill');
      const progOuter = make('div', 'progress');
      progOuter.style.height = '10px';
      const bar = make('div', 'progress-bar');
      bar.style.width = '0%';
      bar.setAttribute('role','progressbar');
      bar.setAttribute('aria-valuemin','0');
      bar.setAttribute('aria-valuemax','100');
      bar.setAttribute('aria-valuenow','0');

      // color by severity
      if(val >= 70) bar.classList.add('bg-danger');
      else if(val > 30) bar.classList.add('bg-warning');
      else bar.classList.add('bg-success');

      progOuter.appendChild(bar);
      progWrap.appendChild(progOuter);
      const percentLabel = make('div', 'ms-2 small', val + '%');

      rowInner.appendChild(badge);
      rowInner.appendChild(progWrap);
      rowInner.appendChild(percentLabel);
      row.appendChild(rowInner);
      wrapper.appendChild(row);

      // animate
      setTimeout(()=> animateBar(bar, val), 60);
    });

    return wrapper;
  }

function renderDetailsLists(data, detailsEl){
  detailsEl.innerHTML = ''; // hide JSON section entirely
}

  // Populate the modal UI given the analysis payload
  function populateModal(payload){
    if(!payload) return;
    const scoreEl = q('#why-score');
    const badgeEl = q('#why-badge');
    const idEl = q('#why-artifact-id');
    const breakdownEl = q('#why-breakdown');
    const detailsEl = q('#why-details');
    const reasonsEl = q('#why-reasons');

    if(!scoreEl || !breakdownEl || !detailsEl || !reasonsEl) return;

    // normalize fields and fallback locations
    const finalScore =
      payload.final_score ||
      payload.suspicion_score ||
      (payload.analysis && (payload.analysis.final_score || payload.analysis.suspicion_score)) ||
      0;
    // unify nested structures (if backend nested analysis inside)
    if (payload.analysis && !payload.breakdown && payload.analysis.breakdown) {
      payload.breakdown = payload.analysis.breakdown;
    }
    if (payload.analysis && !payload.ioc_matches && payload.analysis.ioc_matches) {
      payload.ioc_matches = payload.analysis.ioc_matches;
    }
    if (payload.analysis && !payload.yara_matches && payload.analysis.yara_matches) {
      payload.yara_matches = payload.analysis.yara_matches;
    }
    if (payload.analysis && !payload.heuristics && payload.analysis.heuristics) {
      payload.heuristics = payload.analysis.heuristics;
    }
    if (payload.analysis && !payload.reasons && payload.analysis.reasons) {
      payload.reasons = payload.analysis.reasons;
    }

    // Build weight display for top bars
    const weights = payload.weights || (payload.analysis && payload.analysis.weights) || (function(){
      // fallback: try derive from payload.analysis or default to 40/30/30
      return {ioc:0.40, yara:0.30, heuristics:0.30};
    })();

    // Top header: clean existing
    badgeEl.innerHTML = '';
    const wb = renderWeightBars(weights);
    badgeEl.appendChild(wb);

    // component breakdown: payload.breakdown or components
    const breakdown = payload.breakdown || payload.final_breakdown || (payload.components && {
      ioc_component: payload.components.ioc && payload.components.ioc.score,
      yara_component: payload.components.yara && payload.components.yara.score,
      heuristics_component: payload.components.heuristics && payload.components.heuristics.score,

    }) || {};

    // clear and add component bars
    breakdownEl.innerHTML = '';
    breakdownEl.appendChild(renderComponentBars(breakdown, weights));

    // details lists (ioc/yara/heuristics)
    renderDetailsLists(payload, detailsEl);

    // reasons list
    reasonsEl.innerHTML = '';
    const reasons = payload.reasons || (payload.analysis && payload.analysis.reasons) || [];
    if(Array.isArray(reasons) && reasons.length){
      reasons.forEach(r => {
        const li = make('li', 'small', (typeof r === 'string' ? r : (r.msg || JSON.stringify(r))));
        reasonsEl.appendChild(li);
      });
    } else {
      reasonsEl.innerHTML = '<li class="small text-muted">No summary reasons available.</li>';
    }
  }

  // Copy JSON button behavior
  function wireCopyJson(payloadProvider){
    const copyBtn = q('#copyWhyBtn');
    if(!copyBtn) return;
    copyBtn.addEventListener('click', function(){
      try {
        const payload = payloadProvider();
        if(!payload) return;
        const txt = JSON.stringify(payload, null, 2);
        if(navigator.clipboard && navigator.clipboard.writeText){
          navigator.clipboard.writeText(txt).then(function(){
            const prev = copyBtn.textContent;
            copyBtn.textContent = 'Copied ✓';
            setTimeout(()=> copyBtn.textContent = prev, 1200);
          }).catch(function(){
            fallbackCopy(txt, copyBtn);
          });
        } else {
          fallbackCopy(txt, copyBtn);
        }
      } catch(e){
        console.warn('copy failed', e);
      }
    });
  }

  function fallbackCopy(text, btn){
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      const prev = btn.textContent;
      btn.textContent = 'Copied ✓';
      setTimeout(()=> btn.textContent = prev, 1200);
    } catch(e){
      alert('Copy failed. Open console to access JSON.');
    }
    ta.remove();
  }

  // Main wiring: attach click handlers to .why-btn (idempotent)
  function attachWhyButtons(root){
    root = root || document;
    qa('.why-btn', root).forEach(btn => {
      if(btn.getAttribute('data-why-bound') === '1') return;
      btn.setAttribute('data-why-bound','1');

      btn.addEventListener('click', function(ev){
        // parse payload from data-analysis (stringified JSON) or data attributes
        const raw = btn.getAttribute('data-analysis') || btn.dataset.analysis;
        let payload = safeParse(raw);
        // sometimes the compact_blob is already an object set by Jinja; dataset may have it as object in some browsers
        if(!payload){
          // fallback: try to pick fields on the button itself
          const aid = btn.getAttribute('data-artifact') || btn.dataset.artifact;
          payload = { artifact_id: aid, final_score: 0, reasons: ['no analysis available'] };
        }

        // populate modal before Bootstrap shows it (modal is in DOM already)
        populateModal(payload);

        // wire copy button to always copy the most recent payload shown
        wireCopyJson(()=> payload);
      });
    });
  }

  // boot
  document.addEventListener('DOMContentLoaded', function(){
    attachWhyButtons(document);
    // defensive: attach again a tick later in case template inserted dynamically
    setTimeout(()=> attachWhyButtons(document), 120);
  });

  // Observe DOM mutations to attach handlers to new elements
  const mo = new MutationObserver(function(muts){
    attachWhyButtons(document);
  });
  mo.observe(document.body, { childList:true, subtree:true });

})();