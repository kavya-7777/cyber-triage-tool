// static/js/upload.js 
document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('uploadForm');
    const status = document.getElementById('uploadStatus');

    if (!form) return;

    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        status.innerHTML = '<span class="text-info">Uploading...</span>';

        const fd = new FormData(form);
        const caseId = fd.get('case_id');
        const uploader = fd.get('uploader');
        const fileObj = fd.get('file');
        const fileName = fileObj && fileObj.name ? fileObj.name : null;

        // Handle empty file selection
        if (!fileName) {
            status.innerHTML = `
                <div class="alert alert-warning mt-3" role="alert">
                    ⚠️ No file selected. Please choose a file before uploading.
                </div>
            `;
            return;
        }

        try {
            const resp = await fetch(form.action, { method: 'POST', body: fd });
            let data = {};
            try {
                data = await resp.json();
            } catch {
                // ignore non-JSON responses
            }

            if (resp.ok && !data.error) {
                status.innerHTML = `
                    <div class="alert alert-success mt-3" role="alert">
                        ✅ Upload complete — File <strong>${fileName}</strong> uploaded successfully.
                    </div>
                `;
            } else {
                const errMsg = data.error || "Upload failed due to server error.";
                status.innerHTML = `
                    <div class="alert alert-danger mt-3" role="alert">
                        ❌ Upload failed — ${errMsg}
                    </div>
                `;
            }
        } catch (err) {
            status.innerHTML = `
                <div class="alert alert-danger mt-3" role="alert">
                    ❌ Upload error — ${err.message}
                </div>
            `;
        }
    });
});
