/* Session-only file queue. Files stay in the browser; accepted jobs live on the server. */
function uploader() {
  const raw = document.getElementById('workflows-data');
  const rawTypes = document.getElementById('log-types-data');
  const typeLabels = rawTypes ? JSON.parse(rawTypes.textContent) : {};
  const key = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
  const terminal = new Set(['completed', 'partial', 'failed', 'cancelled', 'unavailable']);
  return {
    rows: [], dragging: false, submitting: false, stopped: false, error: '', hasSubmitted: false, issuesOnly: false,
    demoMode: false, signedIn: false, maxBytes: 0, maxFiles: 50, allWorkflows: raw ? JSON.parse(raw.textContent) : [],
    isPrivate: false, caseMode: 'none', caseId: '', caseName: '', cases: [], casesLoaded: false, casesError: '',
    activeCaseId: null, caseKey: '', caseKeyName: '', caseBusy: false, caseLocked: false,
    active: 0, requestSlots: 4, previewActive: 0, pauseUntil: 0, _queueTimer: null, _pollTimer: null, _pollAfter: 0, _unload: null, destroyed: false, leaving: false,
    init() {
      this.demoMode = this.$el.dataset.demoMode === 'true';
      this.signedIn = this.$el.dataset.signedIn === 'true';
      this.maxBytes = Number(this.$el.dataset.maxBytes);
      this.maxFiles = Math.max(1, Math.min(500, Number(this.$el.dataset.maxFiles) || 50));
      this.requestSlots = Math.max(1, Math.min(4, Number(this.$el.dataset.uploadSlots) || 4));
      this._unload = event => {
        if (this.selectionLocked && !this.leaving) { event.preventDefault(); event.returnValue = ''; }
      };
      window.addEventListener('beforeunload', this._unload);
    },
    destroy() {
      this.destroyed = true;
      clearTimeout(this._queueTimer); clearTimeout(this._pollTimer);
      window.removeEventListener('beforeunload', this._unload);
      for (const row of this.rows) { row.previewController?.abort(); row.xhr?.abort(); }
    },
    get previewsPending() { return this.rows.some(r => r.state === 'preview'); },
    get selectionLocked() { return this.submitting || this.active > 0 || this.caseBusy; },
    get acceptedCount() { return this.rows.filter(r => r.jobId).length; },
    get readyCount() { return this.rows.filter(r => r.state === 'ready' && r.workflowId).length; },
    get retryCount() { return this.rows.filter(r => ['error', 'stopped'].includes(r.state) && r.workflowId).length; },
    get attentionCount() { return this.rows.filter(r => ['invalid', 'error', 'uncertain', 'stopped'].includes(r.state)).length; },
    get visibleRows() { return this.issuesOnly ? this.rows.filter(r => ['invalid', 'error', 'uncertain', 'stopped'].includes(r.state)) : this.rows; },
    get canSubmit() { return !!this.rows.length && this.readyCount === this.rows.length && !this.selectionLocked && !this.demoMode; },
    get allSubmitted() { return this.rows.length > 0 && this.acceptedCount === this.rows.length; },
    get transferringCount() { return this.rows.filter(r => r.state === 'uploading').length; },
    get confirmingCount() { return this.rows.filter(r => r.state === 'accepting').length; },
    get queuedCount() { return this.rows.filter(r => ['queued', 'waiting'].includes(r.state)).length; },
    get transfersFinished() { return !this.transferringCount && !this.queuedCount && this.confirmingCount > 0; },
    get totalBytes() { return this.rows.reduce((n, r) => n + r.file.size, 0); },
    get uploadedBytes() { return this.rows.reduce((n, r) => n + (r.jobId ? r.file.size : r.loaded), 0); },
    get percent() { return this.totalBytes ? Math.round(this.uploadedBytes / this.totalBytes * 100) : 0; },
    get submissionTitle() {
      if (this.allSubmitted) return `${this.acceptedCount} ${this.acceptedCount === 1 ? 'file' : 'files'} submitted`;
      if (this.stopped && this.active) return 'Stopping uploads…';
      if (this.transfersFinished) return 'Finalizing submissions…';
      if (this.submitting) return `Submitting ${this.rows.length} files…`;
      return `${this.acceptedCount} of ${this.rows.length} files submitted`;
    },
    get submissionHint() {
      if (this.allSubmitted) return 'You can close this tab. Analysis continues in the background.';
      if (this.selectionLocked) return this.transfersFinished
        ? 'Files transferred. Waiting for the server to confirm receipt before you leave.'
        : 'Keep this tab open while your files are being submitted. You do not need to wait for analysis.';
      return 'Submitted files continue in the background. Review the remaining files below before leaving.';
    },
    get submitLabel() {
      if (this.caseBusy) return 'Preparing case…';
      if (this.previewsPending) return 'Checking files…';
      return this.rows.length > 1 ? `Analyze ${this.rows.length} files` : 'Analyze';
    },
    // Submission progress counts an accepted file as submitted, whatever its analysis did.
    phase(row) { return row.jobId ? 'ok' : this.tone(row); },
    phaseCount(tone) { return this.rows.filter(r => this.phase(r) === tone).length; },
    segment(tone) { return 'width:' + (this.rows.length ? this.phaseCount(tone) / this.rows.length * 100 : 0) + '%'; },
    get panelTone() {
      if (this.allSubmitted) return 'ok';
      if (this.selectionLocked) return 'busy';
      return this.attentionCount ? 'warn' : 'idle';
    },
    get summaryParts() {
      const parts = [{ tone: 'ok', text: `${this.acceptedCount} submitted` }];
      if (this.transferringCount) parts.push({ tone: 'busy', text: `${this.transferringCount} uploading` });
      if (this.confirmingCount) parts.push({ tone: 'busy', text: `${this.confirmingCount} finalizing` });
      if (this.queuedCount) parts.push({ tone: 'idle', text: `${this.queuedCount} queued` });
      const warn = this.phaseCount('warn'), bad = this.phaseCount('bad');
      if (warn) parts.push({ tone: 'warn', text: `${warn} ${warn === 1 ? 'needs' : 'need'} attention` });
      if (bad) parts.push({ tone: 'bad', text: `${bad} failed` });
      return parts;
    },
    formatBytes(n) {
      if (n < 1024) return n + ' B';
      if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
      return n < 1073741824 ? (n / 1048576).toFixed(1) + ' MB' : (n / 1073741824).toFixed(2) + ' GB';
    },
    typeLabel(row) {
      const type = row.override !== 'auto' ? row.override : row.detectedType;
      return typeLabels[type] || (row.override !== 'auto' ? row.override : row.detectedLabel) || 'Auto-detect';
    },
    knownType(row) { return row.override !== 'auto' || (row.detectedType && row.detectedType !== 'unknown'); },
    workflowLabel(row) { return this.allWorkflows.find(w => String(w.id) === String(row.workflowId))?.name || ''; },
    editable(row) { return !this.selectionLocked && ['preview', 'ready', 'invalid', 'error', 'stopped'].includes(row.state); },
    compatible(row) {
      const type = row.override !== 'auto' ? row.override : row.detectedType;
      if (!type) return this.allWorkflows;
      return this.allWorkflows.filter(w => !w.log_types.length || w.log_types.includes(type));
    },
    syncWorkflow(row) {
      const choices = this.compatible(row);
      if (!choices.some(w => String(w.id) === String(row.workflowId))) {
        row.workflowId = String((choices.find(w => w.is_default) || choices[0])?.id || '');
      }
      if (row.state === 'invalid' && row.file.size <= this.maxBytes && row.workflowId) row.state = 'ready';
      if (row.state === 'ready' && !row.workflowId) row.state = 'invalid';
      this.$nextTick(() => {
        const select = document.getElementById('workflow-' + row.id);
        if (select) select.value = row.workflowId;
      });
    },
    applyWorkflow(row) {
      for (const other of this.rows) {
        if (this.editable(other) && this.compatible(other).some(w => String(w.id) === row.workflowId)) {
          other.workflowId = row.workflowId; this.syncWorkflow(other);
        }
      }
    },
    onDrop(event) {
      this.dragging = false;
      if (this.demoMode || this.selectionLocked || this.hasSubmitted) return;
      const entries = Array.from(event.dataTransfer.items || []);
      if (entries.some(item => item.webkitGetAsEntry?.()?.isDirectory)) {
        this.error = 'Choose individual files. Folder uploads are not supported.'; return;
      }
      this.addFiles(event.dataTransfer.files);
    },
    onFileChange(event) { this.addFiles(event.target.files); event.target.value = ''; },
    addFiles(files) {
      if (this.demoMode || this.selectionLocked || this.hasSubmitted) return;
      this.error = '';
      const incoming = Array.from(files);
      const available = Math.max(0, this.maxFiles - this.rows.length);
      if (incoming.length > available) {
        const excess = incoming.length - available;
        this.error = `Select up to ${this.maxFiles} ${this.maxFiles === 1 ? 'file' : 'files'}. ${excess} extra ${excess === 1 ? 'file was' : 'files were'} not added.`;
      }
      for (const file of incoming.slice(0, available)) {
        const tooLarge = file.size > this.maxBytes;
        this.rows.push({ id: key(), file, name: file.name, state: tooLarge ? 'invalid' : 'preview',
          detectedType: '', detectedLabel: '', override: 'auto', workflowId: '', previewStarted: false, typeEditing: false,
          previewController: null, message: tooLarge ? 'File exceeds the upload size limit.' : '',
          loaded: 0, xhr: null, key: this.signedIn ? key() : null, jobId: null, jobStatus: '', reused: false, snapshot: null });
      }
      this.pumpPreviews();
    },
    remove(row) {
      if (this.selectionLocked || row.jobId) return;
      row.previewController?.abort();
      this.rows = this.rows.filter(r => r.id !== row.id);
      if (!this.attentionCount) this.issuesOnly = false;
    },
    startOver() {
      if (this.selectionLocked) return;
      for (const row of this.rows) row.previewController?.abort();
      clearTimeout(this._pollTimer); this._pollTimer = null; this._pollAfter = 0;
      this.rows = []; this.hasSubmitted = false; this.issuesOnly = false; this.stopped = false; this.error = '';
      this.activeCaseId = null; this.caseLocked = false; this.caseKey = ''; this.caseKeyName = '';
      this.caseMode = 'none'; this.caseId = ''; this.caseName = '';
    },
    pumpPreviews() {
      if (this.destroyed) return;
      for (const row of this.rows) {
        if (this.previewActive >= 2) break;
        if (row.state !== 'preview' || row.previewStarted) continue;
        row.previewStarted = true; this.previewActive++;
        this.detectType(row).finally(() => { this.previewActive--; this.pumpPreviews(); });
      }
    },
    async detectType(row) {
      row.previewController = new AbortController();
      try {
        const body = new FormData();
        body.append('file', row.file.slice(0, 65536), row.name);
        const response = await fetch('/detect-preview', { method: 'POST', body, signal: row.previewController.signal });
        if (!response.ok) throw new Error('Preview unavailable');
        const data = await response.json();
        if (!this.rows.some(r => r.id === row.id) || this.destroyed) return;
        row.detectedType = data.log_type; row.detectedLabel = data.label;
      } catch (error) {
        if (error.name === 'AbortError' || !this.rows.some(r => r.id === row.id)) return;
        row.message = 'Preview unavailable. The server will detect the type after upload.';
      } finally {
        if (this.rows.some(r => r.id === row.id) && !this.destroyed) {
          row.state = 'ready'; row.previewController = null; this.syncWorkflow(row);
        }
      }
    },
    async loadCases() {
      if (this.casesLoaded) return;
      this.casesError = '';
      try {
        const response = await fetch('/intel/cases/list.json?limit=500', { headers: { Accept: 'application/json' } });
        if (!response.ok) throw new Error('Unable to load cases.');
        this.cases = await response.json(); this.casesLoaded = true;
      } catch (error) { this.casesError = error.message; }
    },
    async prepareCase() {
      if (this.caseMode === 'none') return null;
      if (this.caseMode === 'existing') {
        if (!this.caseId) throw new Error('Choose a case.');
        return Number(this.caseId);
      }
      const name = this.caseName.trim();
      if (!name) throw new Error('Enter a case name.');
      if (this.activeCaseId) return this.activeCaseId;
      if (name !== this.caseKeyName) { this.caseKey = key(); this.caseKeyName = name; }
      const response = await fetch('/api/v1/cases', { method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'Idempotency-Key': this.caseKey },
        body: JSON.stringify({ name }) });
      const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Unable to create case.');
      return data.case_id;
    },
    async submitUpload(event) {
      if (!this.canSubmit) return;
      this.error = ''; this.caseBusy = true;
      try {
        this.activeCaseId = await this.prepareCase();
        this.caseLocked = true;
        this.action = event.target.getAttribute('action');
        this.stopped = false; this.pauseUntil = 0; this.submitting = true; this.hasSubmitted = true; this.issuesOnly = false;
        for (const row of this.rows.filter(r => r.state === 'ready' && r.workflowId)) {
          row.snapshot = { workflow_id: row.workflowId, log_type_override: row.override,
            is_private: this.isPrivate ? 'true' : 'false', case_id: this.activeCaseId };
          row.state = 'queued'; row.message = '';
        }
        this.pump();
      } catch (error) { this.error = error.message; }
      finally { this.caseBusy = false; }
    },
    pump() {
      clearTimeout(this._queueTimer);
      if (this.destroyed || this.stopped) return;
      if (Date.now() < this.pauseUntil) {
        this._queueTimer = setTimeout(() => this.pump(), this.pauseUntil - Date.now()); return;
      }
      for (const row of this.rows) {
        // Start the next transfer as soon as bytes finish sending, while earlier
        // requests are confirmed. Bound both network transfers and server work.
        if (this.transferringCount >= 2 || this.active >= this.requestSlots) break;
        if (!['queued', 'waiting'].includes(row.state)) continue;
        this.active++;
        this.upload(row).finally(() => { this.active--; this.pump(); });
      }
      if (!this.active && !this.rows.some(r => ['queued', 'waiting'].includes(r.state))) this.submitting = false;
    },
    upload(row) {
      return new Promise(resolve => {
        row.state = 'uploading'; row.loaded = 0;
        const xhr = new XMLHttpRequest(); row.xhr = xhr;
        xhr.open('POST', this.action || '/upload', true);
        xhr.setRequestHeader('Accept', 'application/json');
        if (row.key) xhr.setRequestHeader('Idempotency-Key', row.key);
        xhr.upload.onprogress = event => {
          if (event.lengthComputable) row.loaded = Math.min(row.file.size, row.file.size * event.loaded / event.total);
        };
        xhr.upload.onload = () => {
          row.loaded = row.file.size; row.state = 'accepting'; this.pump();
        };
        const finish = () => { row.xhr = null; resolve(); };
        xhr.onload = async () => {
          let data = {};
          try { data = JSON.parse(xhr.responseText); } catch (_) { /* proxy error */ }
          if (xhr.status >= 200 && xhr.status < 300 && data.job_id) {
            this.accept(row, data);
          } else if (xhr.status === 429) {
            const header = xhr.getResponseHeader('Retry-After');
            const delay = /^\d+$/.test(header || '') ? Number(header) * 1000 : Math.max(0, Date.parse(header) - Date.now()) || 60000;
            this.pauseUntil = Date.now() + Math.max(1000, delay);
            row.state = 'waiting'; row.message = 'The server is busy; retrying automatically.';
          } else {
            row.state = xhr.status >= 500 ? 'uncertain' : 'error';
            row.message = typeof data.detail === 'string' ? data.detail : `Upload failed (HTTP ${xhr.status}).`;
            if (row.state === 'uncertain') row.message += ' Check the submission outcome before retrying.';
            if (xhr.status >= 500 && row.key) await this.reconcile(row);
          }
          finish();
        };
        const uncertain = async () => {
          row.state = 'uncertain'; row.message = 'Upload outcome unknown. Check Jobs before retrying.';
          if (row.key) await this.reconcile(row);
          finish();
        };
        xhr.onerror = uncertain; xhr.onabort = uncertain;
        const body = new FormData(); body.append('file', row.file, row.name);
        for (const [name, value] of Object.entries(row.snapshot)) if (value !== null) body.append(name, value);
        xhr.send(body);
      });
    },
    accept(row, data) {
      row.jobId = data.job_id; row.jobStatus = data.status; row.reused = data.reused;
      row.state = 'accepted'; row.loaded = row.file.size; row.message = data.reused ? 'Existing analysis reused.' : '';
      if (this.rows.length === 1 && !this.stopped && !this.destroyed) {
        // The browser runs `beforeunload` inside this assignment, before the upload that
        // accepted the job has settled, so the guard would still see a transfer in flight.
        this.leaving = true; window.location.href = data.job_url; return;
      }
      this.schedulePoll();
    },
    async reconcile(row) {
      try {
        const response = await fetch('/api/v1/submissions/' + encodeURIComponent(row.key), { headers: { Accept: 'application/json' } });
        if (response.ok) { this.accept(row, await response.json()); return true; }
        if (response.status === 404) return false;
        if (response.status === 410) { row.state = 'error'; row.message = 'The accepted job was deleted. Choose the file again to submit a new job.'; }
      } catch (_) { /* retain the uncertain state */ }
      return false;
    },
    async retry(row) {
      if (this.submitting || this.active || this.caseBusy || this.demoMode) return;
      if (row.state === 'uncertain') {
        if (row.key && await this.reconcile(row)) return;
        // Same key and frozen options safely arbitrate an original request still finishing.
      } else {
        row.key = this.signedIn ? key() : null;
        row.snapshot = { workflow_id: row.workflowId, log_type_override: row.override,
          is_private: this.isPrivate ? 'true' : 'false', case_id: this.activeCaseId };
      }
      this.stopped = false; this.submitting = true; this.issuesOnly = false; row.state = 'queued'; row.message = ''; this.pump();
    },
    retryFailed() {
      if (this.selectionLocked || this.demoMode) return;
      for (const row of this.rows.filter(r => ['error', 'stopped'].includes(r.state) && r.workflowId && r.snapshot)) {
        row.key = this.signedIn ? key() : null; row.state = 'queued'; row.message = '';
        row.snapshot = { workflow_id: row.workflowId, log_type_override: row.override,
          is_private: this.isPrivate ? 'true' : 'false', case_id: this.activeCaseId };
      }
      this.stopped = false; this.submitting = true; this.issuesOnly = false; this.pump();
    },
    cancelUpload() {
      this.stopped = true; this.submitting = false; clearTimeout(this._queueTimer);
      for (const row of this.rows) {
        if (['queued', 'waiting'].includes(row.state)) { row.state = 'stopped'; row.message = 'Not submitted.'; }
        if (row.xhr) row.xhr.abort();
      }
    },
    schedulePoll() {
      if (this._pollTimer || this.destroyed) return;
      if (!this.rows.some(r => r.jobId && !terminal.has(r.jobStatus))) return;
      this._pollTimer = setTimeout(() => { this._pollTimer = null; this.poll(); }, document.hidden ? 15000 : 3000);
    },
    async poll() {
      const activeIds = [...new Set(this.rows.filter(r => r.jobId && !terminal.has(r.jobStatus)).map(r => r.jobId))].sort((a, b) => a - b);
      if (!activeIds.length || this.destroyed) return;
      // Rotate through at most 50 jobs per tick. Larger selections retain the
      // same request rate, and completing jobs cannot starve later IDs.
      const after = activeIds.findIndex(id => id > this._pollAfter);
      const ids = activeIds.slice(after === -1 ? 0 : after, (after === -1 ? 0 : after) + 50);
      this._pollAfter = ids[ids.length - 1];
      try {
        const response = await fetch('/api/v1/jobs?ids=' + ids.join(','), { headers: { Accept: 'application/json' } });
        if (response.ok) {
          const data = await response.json();
          for (const row of this.rows) {
            const job = data.jobs.find(j => j.job_id === row.jobId);
            if (job) { row.jobStatus = job.status; if (job.error) row.message = job.error; }
            if (data.unavailable_ids.includes(row.jobId)) { row.jobStatus = 'unavailable'; row.message = 'Job no longer available.'; }
          }
        }
      } catch (_) { /* accepted work continues; retry the next lightweight poll */ }
      this.schedulePoll();
    },
    label(row) {
      if (row.jobId) return ({ pending: 'Queued for analysis', running: 'Analyzing', completed: 'Analysis complete', partial: 'Partially analyzed',
        failed: 'Analysis failed', cancelled: 'Cancelled', unavailable: 'Job unavailable' })[row.jobStatus] || 'Submitted';
      if (row.state === 'invalid') return row.file.size > this.maxBytes ? 'Too large' : (this.knownType(row) ? 'No workflow' : 'Needs a log type');
      const percent = row.file.size ? Math.round(row.loaded / row.file.size * 100) : 0;
      return ({ preview: 'Detecting type', ready: 'Ready', queued: 'Queued', uploading: `Uploading ${percent}%`, accepting: 'Confirming receipt',
        waiting: 'Waiting for capacity', stopped: 'Not submitted', error: 'Upload failed', uncertain: 'Outcome unknown' })[row.state];
    },
    // The detail under a row's label: the server's message, or what to do about an invalid row.
    note(row) {
      if (row.message) return row.message;
      if (row.state !== 'invalid') return '';
      return this.knownType(row) ? 'No workflow accepts this log type. Choose another type or remove the file.'
        : 'The log type was not detected. Choose a log type or remove the file.';
    },
    // One of idle | busy | ok | warn | bad. The template colours a row from this alone.
    tone(row) {
      if (row.jobId) return ({ completed: 'ok', partial: 'warn', failed: 'bad', cancelled: 'idle', unavailable: 'bad' })[row.jobStatus] || 'ok';
      if (row.state === 'invalid') return row.file.size > this.maxBytes ? 'bad' : 'warn';
      return ({ preview: 'busy', uploading: 'busy', accepting: 'busy', stopped: 'warn', error: 'bad', uncertain: 'warn' })[row.state] || 'idle';
    },
    // A name from the icon dictionary in partials/_icons.html.
    glyph(row) {
      const tone = this.tone(row);
      if (tone === 'idle') return !row.jobId && ['queued', 'waiting'].includes(row.state) ? 'clock' : 'file';
      return ({ busy: 'spinner', ok: 'check', warn: 'alert', bad: 'fail' })[tone];
    },
    // The job-status badge classes /jobs uses, so the two pages share one palette.
    badge(row) {
      if (row.jobId) return ({ pending: 'badge-pending', running: 'badge-running', completed: 'badge-completed', partial: 'badge-partial',
        failed: 'badge-failed', cancelled: 'badge-cancelled', unavailable: 'badge-failed' })[row.jobStatus] || 'badge-completed';
      return ({ idle: 'badge-pending', busy: 'badge-running', warn: 'badge-partial', bad: 'badge-failed' })[this.tone(row)];
    }
  };
}
