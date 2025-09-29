// static/js/upload.js — minimal AJAX uploader + response preview
document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('uploadForm');
    const status = document.getElementById('uploadStatus');
    const showRaw = document.getElementById('showRawJson');


    if (!form) return;

    form.addEventListener('submit', async function(e){
        e.preventDefault();
        status.innerHTML = 'Uploading...';
        const fd = new FormData(form);


        try {
            const resp = await fetch(form.action, { method: 'POST', body: fd });
            let text;
            try {
                const json = await resp.json();
                text = JSON.stringify(json, null, 2);
            } catch (err) {
                text = await resp.text();
            }
            if (showRaw && showRaw.checked) {
                status.innerHTML = `<pre style="white-space:pre-wrap">${text}</pre>`;
            } else {
                // Try to show a compact summary
            try {
                const j = JSON.parse(text);
                const files_processed = j.per_file ? j.per_file.length : (j.metadata ? 1 : 0);
                const score = j.metadata && j.metadata.analysis ? (j.metadata.analysis.final_score || j.metadata.analysis.suspicion_score) : (j.per_file && j.per_file[0] && j.per_file[0].final_score);
                status.innerHTML = `<div class="alert alert-success">Upload complete — files processed: ${files_processed}. <br/> Case: ${j.case_id || ''} <br/> Score: ${score !== undefined ? score : 'N/A'}</div><pre style="white-space:pre-wrap">${text}</pre>`;
            } catch (e) {
                status.innerHTML = `<pre style="white-space:pre-wrap">${text}</pre>`;
            }
        }   
    } catch (err) {
        status.textContent = 'Upload failed: ' + err;
    }
    });
});