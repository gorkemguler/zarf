(() => {
  'use strict';

  const i18n = {
    en: {
      tagline: 'Offline .eml Phishing Autopsy & Forensics',
      offline_badge: '100% OFFLINE · 0 NETWORK CALLS',
      paste_raw: 'Paste Raw .eml',
      upload_eml: 'Upload .eml',
      drop_title: 'Drop .eml files here',
      drop_sub: 'Local memory only · never uploaded externally',
      session_queue: 'SESSION QUEUE',
      no_history: 'No emails inspected yet.',
      demo_specimens: 'SYNTHETIC DEMO SPECIMENS',
      welcome_h1: 'Dissect suspicious .eml artifacts completely offline.',
      welcome_lead: 'Drop an .eml file or launch a synthetic phishing specimen to inspect SMTP Received hop graphs, RFC 6376 DKIM body-hash verification, HTML smuggling payloads, Punycode/homoglyph URLs, and static attachment forensics.',
      choose_eml: 'Choose .eml File(s)',
      lbl_from: 'From:',
      lbl_date: 'Date:',
      lbl_auth: 'Auth:',
      btn_takedown: 'Takedown Draft',
      tab_overview: 'Findings & Overview',
      tab_hops: 'Hop Graph & Auth',
      tab_body: 'Body & Smuggling',
      tab_urls: 'URLs & Homoglyphs',
      tab_attachments: 'Attachment Lab',
      tab_iocs: 'IOCs & Exports',
      filter_all: 'All',
      hdr_findings: 'Explainable Risk Findings',
      hdr_actions: 'Recommended SOC Actions',
      hdr_manifest: 'Evidence Integrity Manifest',
      hdr_hop_graph: 'SMTP Received Hop Graph (Origin → Delivery)',
      hdr_identity: 'Identity Alignment Matrix',
      hdr_auth_dkim: 'SPF / DKIM / DMARC & Offline RFC 6376 bh= Check',
      sub_preview: 'Safe Offline Preview',
      sub_smuggling: 'Smuggling & Stealth',
      sub_rawhtml: 'Raw HTML',
      sub_plain: 'Plain Text',
      sub_headers: 'All Raw Headers',
      hdr_urls: 'Extracted URLs, Homoglyphs & Anchor Diffs',
      copy_defanged_urls: 'Copy Defanged URLs',
      hdr_defanged_iocs: 'Defanged IOCs',
      copy_all: 'Copy All',
      hdr_takedown: 'Abuse / Phishing Takedown Draft',
      copy: 'Copy',
      paste_modal_title: 'Paste Raw RFC 5322 / .eml Content',
      cancel: 'Cancel',
      run_autopsy: 'Run Offline Autopsy',
      quit_app: 'Quit',
      no_attachments: 'No attachments found in this email.',
      no_urls: 'No HTTP/HTTPS URLs extracted from this email.',
      toast_analyzed: 'Analyzed',
      toast_stopped: 'Zarf server stopped. You may close this tab.',
    },
    tr: {
      tagline: 'Çevrimdışı .eml Phishing Otopsi & Adli Analiz',
      offline_badge: '%100 ÇEVRİMDIŞI · 0 AĞ İSTEĞİ',
      paste_raw: 'Ham .eml Yapıştır',
      upload_eml: '.eml Yükle',
      drop_title: '.eml dosyalarını buraya bırak',
      drop_sub: 'Sadece yerel bellek · dışarıya veri gönderilmez',
      session_queue: 'OTURUM KUYRUĞU',
      no_history: 'Henüz incelenmiş e-posta yok.',
      demo_specimens: 'SENTETİK DEMO ÖRNEKLERİ',
      welcome_h1: 'Şüpheli .eml dosyalarını %100 çevrimdışı parçala.',
      welcome_lead: 'Bir .eml dosyası bırak veya sentetik oltalama örneklerinden birini aç: SMTP hop grafiği, çevrimdışı RFC 6376 DKIM gövde hash doğrulaması, HTML smuggling, Punycode/homoglyph URL ve statik ek dosya adli analizi.',
      choose_eml: '.eml Dosyası Seç',
      lbl_from: 'Gönderen:',
      lbl_date: 'Tarih:',
      lbl_auth: 'Doğrulama:',
      btn_takedown: 'Takedown Taslağı',
      tab_overview: 'Bulgular & Özet',
      tab_hops: 'Hop Grafiği & Auth',
      tab_body: 'Gövde & Smuggling',
      tab_urls: 'URL & Homoglyph',
      tab_attachments: 'Ek Dosya Lab',
      tab_iocs: 'IOC & Dışa Aktar',
      filter_all: 'Tümü',
      hdr_findings: 'Açıklanabilir Risk Bulguları',
      hdr_actions: 'Önerilen SOC Aksiyonları',
      hdr_manifest: 'Kanıt Bütünlük Manifestosu',
      hdr_hop_graph: 'SMTP Received Hop Grafiği (Kaynak → Teslim)',
      hdr_identity: 'Kimlik Hizalama Matrisi',
      hdr_auth_dkim: 'SPF / DKIM / DMARC & Çevrimdışı RFC 6376 bh= Kontrolü',
      sub_preview: 'Güvenli Çevrimdışı Önizleme',
      sub_smuggling: 'Smuggling & Gizleme',
      sub_rawhtml: 'Ham HTML',
      sub_plain: 'Düz Metin',
      sub_headers: 'Tüm Ham Başlıklar',
      hdr_urls: 'Çıkarılan URL, Homoglyph & Çapa Farkları',
      copy_defanged_urls: 'Defanged URL Kopyala',
      hdr_defanged_iocs: 'Defanged IOC Listesi',
      copy_all: 'Tümünü Kopyala',
      hdr_takedown: 'Abuse / Takedown İhbar Taslağı',
      copy: 'Kopyala',
      paste_modal_title: 'Ham RFC 5322 / .eml İçeriği Yapıştır',
      cancel: 'İptal',
      run_autopsy: 'Çevrimdışı Otopsi Başlat',
      quit_app: 'Kapat',
      no_attachments: 'Bu e-postada ek dosya bulunamadı.',
      no_urls: 'Bu e-postadan HTTP/HTTPS bağlantısı çıkarılamadı.',
      toast_analyzed: 'Analiz edildi',
      toast_stopped: 'Zarf sunucusu durduruldu. Bu sekmeyi kapatabilirsiniz.',
    },
  };

  let state = {
    lang: 'en',
    takedownLang: 'en',
    currentItem: null,
    history: [],
    samples: [],
    sevFilter: 'ALL',
  };

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  function esc(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function showToast(msg) {
    const el = $('#toast');
    el.textContent = msg;
    el.classList.remove('hidden');
    clearTimeout(el._timer);
    el._timer = setTimeout(() => el.classList.add('hidden'), 2400);
  }

  async function copyText(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      showToast(label || 'Copied to clipboard');
    } catch {
      showToast('Clipboard blocked by browser');
    }
  }

  function applyLang(lang) {
    state.lang = lang;
    state.takedownLang = lang;
    $$('.lang-btn').forEach((b) => b.classList.toggle('active', b.dataset.lang === lang));
    const dict = i18n[lang] || i18n.en;
    $$('[data-i18n]').forEach((el) => {
      const k = el.dataset.i18n;
      if (dict[k]) el.textContent = dict[k];
    });
    if (state.currentItem) {
      loadTakedownPreview(state.currentItem.id, state.takedownLang);
    }
  }

  async function init() {
    bindEvents();
    try {
      const h = await fetch('/api/health').then((r) => r.json());
      if (h.version) $('#tool-version').textContent = 'v' + h.version;
      if (h.can_stop) {
        const stopBtn = $('#btn-stop-server');
        stopBtn.classList.remove('hidden');
        stopBtn.addEventListener('click', async () => {
          try {
            await fetch('/api/shutdown', { method: 'POST', headers: { 'X-Zarf-Stop': '1' } });
          } catch {}
          showToast(i18n[state.lang].toast_stopped);
        });
      }
    } catch {}

    await Promise.all([loadSamples(), loadHistory()]);
    if (state.history.length > 0) {
      await selectReport(state.history[0].id);
    }
  }

  function bindEvents() {
    $$('.lang-btn').forEach((b) => b.addEventListener('click', () => applyLang(b.dataset.lang)));

    // Tabs
    $$('.tab').forEach((btn) => {
      btn.addEventListener('click', () => {
        const name = btn.dataset.tab;
        $$('.tab').forEach((t) => t.classList.toggle('active', t === btn));
        $$('.tab-panel').forEach((p) => p.classList.toggle('active', p.id === 'panel-' + name));
      });
    });

    // Body Subtabs
    $$('.subtab').forEach((btn) => {
      btn.addEventListener('click', () => {
        const name = btn.dataset.subtab;
        $$('.subtab').forEach((t) => t.classList.toggle('active', t === btn));
        $$('.subpanel').forEach((p) => p.classList.toggle('active', p.id === 'sub-' + name));
      });
    });

    // Severity filters
    $$('#sev-filters .pill').forEach((btn) => {
      btn.addEventListener('click', () => {
        state.sevFilter = btn.dataset.sev;
        $$('#sev-filters .pill').forEach((p) => p.classList.toggle('active', p === btn));
        if (state.currentItem) renderFindings(state.currentItem.report);
      });
    });

    // File upload
    const fileInput = $('#file-input-top');
    fileInput.addEventListener('change', async (e) => {
      if (e.target.files && e.target.files.length) {
        await uploadFiles(Array.from(e.target.files));
        e.target.value = '';
      }
    });

    // Drag & drop (sidebar + whole window)
    const dz = $('#sidebar-dropzone');
    dz.addEventListener('click', () => fileInput.click());
    ['dragenter', 'dragover'].forEach((ev) => {
      document.addEventListener(ev, (e) => {
        e.preventDefault();
        dz.classList.add('dragover');
      });
    });
    ['dragleave', 'drop'].forEach((ev) => {
      document.addEventListener(ev, (e) => {
        e.preventDefault();
        if (ev === 'drop') {
          dz.classList.remove('dragover');
          if (e.dataTransfer && e.dataTransfer.files.length) {
            uploadFiles(Array.from(e.dataTransfer.files));
          }
        }
      });
    });

    // Paste modal
    const openModal = () => {
      $('#paste-modal').classList.remove('hidden');
      $('#paste-textarea').focus();
    };
    const closeModal = () => $('#paste-modal').classList.add('hidden');
    $('#btn-paste-modal').addEventListener('click', openModal);
    $('#btn-welcome-paste').addEventListener('click', openModal);
    $('#btn-close-modal').addEventListener('click', closeModal);
    $('#btn-cancel-modal').addEventListener('click', closeModal);
    $('#btn-submit-paste').addEventListener('click', async () => {
      const raw = $('#paste-textarea').value;
      const fn = $('#paste-filename').value.trim() || 'pasted.eml';
      if (!raw.trim()) {
        showToast('Paste raw .eml content first');
        return;
      }
      closeModal();
      await analyzeRawText(fn, raw);
    });

    // Export buttons
    $$('[data-export]').forEach((btn) => {
      btn.addEventListener('click', () => {
        if (!state.currentItem) return;
        const fmt = btn.dataset.export;
        const url = `/api/export/${state.currentItem.id}/${fmt}?lang=${state.takedownLang}`;
        window.location.href = url;
      });
    });

    // Header search
    $('#header-search').addEventListener('input', (e) => {
      if (state.currentItem) renderAllHeaders(state.currentItem.report, e.target.value);
    });

    // Copy buttons
    $('#hero-sha256').addEventListener('click', () => {
      if (state.currentItem) copyText(state.currentItem.report.evidence.sha256, 'SHA-256 copied');
    });
    $('#btn-copy-urls').addEventListener('click', () => {
      if (!state.currentItem) return;
      const text = (state.currentItem.report.iocs.defanged_urls || []).join('\n');
      copyText(text, 'Defanged URLs copied');
    });
    $('#btn-copy-all-iocs').addEventListener('click', () => {
      copyText($('#iocs-viewer').textContent, 'Defanged IOCs copied');
    });
    $('#btn-copy-takedown').addEventListener('click', () => {
      copyText($('#takedown-viewer').textContent, 'Takedown draft copied');
    });
    $('#btn-takedown-en').addEventListener('click', () => {
      state.takedownLang = 'en';
      if (state.currentItem) loadTakedownPreview(state.currentItem.id, 'en');
    });
    $('#btn-takedown-tr').addEventListener('click', () => {
      state.takedownLang = 'tr';
      if (state.currentItem) loadTakedownPreview(state.currentItem.id, 'tr');
    });
  }

  async function loadSamples() {
    const list = await fetch('/api/samples').then((r) => r.json());
    state.samples = list || [];

    const sidebarHTML = state.samples
      .map(
        (s) => `
      <button class="sample-item" data-sample="${esc(s.id)}">
        <div class="sample-cat">${esc(s.category)}</div>
        <div class="sample-name">${esc(s.name)}</div>
        <div class="sample-desc">${esc(s.description)}</div>
      </button>`
      )
      .join('');
    $('#sample-list').innerHTML = sidebarHTML;

    const welcomeHTML = state.samples
      .map(
        (s) => `
      <button class="welcome-sample-card" data-sample="${esc(s.id)}">
        <div class="sample-cat">${esc(s.category)}</div>
        <div class="sample-name">${esc(s.name)}</div>
        <div class="sample-desc">${esc(s.description)}</div>
      </button>`
      )
      .join('');
    $('#welcome-samples-grid').innerHTML = welcomeHTML;

    $$('[data-sample]').forEach((btn) => {
      btn.addEventListener('click', () => inspectSample(btn.dataset.sample));
    });
  }

  async function inspectSample(id) {
    try {
      const item = await fetch(`/api/samples/${encodeURIComponent(id)}`, { method: 'POST' }).then((r) => r.json());
      if (item.error) {
        showToast(item.error);
        return;
      }
      await loadHistory();
      renderItem(item);
      showToast(`${i18n[state.lang].toast_analyzed}: ${item.filename}`);
    } catch (err) {
      showToast('Failed to inspect sample');
    }
  }

  async function uploadFiles(files) {
    let lastItem = null;
    for (const file of files) {
      const fd = new FormData();
      fd.append('file', file);
      const res = await fetch('/api/analyze', { method: 'POST', body: fd });
      const data = await res.json();
      if (res.ok) {
        lastItem = data;
      } else {
        showToast(`Error (${file.name}): ${data.error || 'failed'}`);
      }
    }
    await loadHistory();
    if (lastItem) {
      renderItem(lastItem);
      showToast(`Analyzed ${files.length} file(s) offline`);
    }
  }

  async function analyzeRawText(filename, raw) {
    const res = await fetch(`/api/analyze?filename=${encodeURIComponent(filename)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'message/rfc822' },
      body: raw,
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Parse error');
      return;
    }
    await loadHistory();
    renderItem(data);
    showToast(`Analyzed ${filename}`);
  }

  async function loadHistory() {
    const list = await fetch('/api/history').then((r) => r.json());
    state.history = list || [];
    $('#history-count').textContent = state.history.length;
    if (!state.history.length) {
      $('#history-list').innerHTML = `<div class="empty-hint">${esc(i18n[state.lang].no_history)}</div>`;
      return;
    }
    $('#history-list').innerHTML = state.history
      .map((it) => {
        const active = state.currentItem && state.currentItem.id === it.id ? 'active' : '';
        return `
        <button class="history-item ${active}" data-id="${esc(it.id)}">
          <div class="history-top">
            <span class="history-file mono">${esc(it.filename)}</span>
            <span class="sev-badge verdict-${esc(it.verdict)}">${it.score}</span>
          </div>
          <div class="history-subj">${esc(it.subject || '(no subject)')}</div>
        </button>`;
      })
      .join('');
    $$('.history-item').forEach((btn) => {
      btn.addEventListener('click', () => selectReport(btn.dataset.id));
    });
  }

  async function selectReport(id) {
    const item = await fetch(`/api/report/${encodeURIComponent(id)}`).then((r) => r.json());
    if (item && item.report) {
      renderItem(item);
    }
  }

  function verdictColorHex(v) {
    switch (v) {
      case 'CRITICAL': return '#ef4444';
      case 'HIGH': return '#f97316';
      case 'MEDIUM': return '#eab308';
      case 'LOW': return '#38bdf8';
      default: return '#22c55e';
    }
  }

  function renderItem(item) {
    state.currentItem = item;
    const rep = item.report;

    $('#welcome-panel').classList.add('hidden');
    $('#report-view').classList.remove('hidden');

    // Update active state in history rail
    $$('.history-item').forEach((el) => el.classList.toggle('active', el.dataset.id === item.id));

    // Score gauge
    const score = rep.score.total || 0;
    const circ = 2 * Math.PI * 50;
    const offset = circ - (score / 100) * circ;
    const fill = $('#gauge-fill');
    fill.style.strokeDashoffset = offset.toFixed(2);
    fill.style.stroke = verdictColorHex(rep.score.verdict);
    $('#score-number').textContent = score;
    $('#score-number').style.color = verdictColorHex(rep.score.verdict);

    const vb = $('#verdict-badge');
    vb.textContent = rep.score.verdict;
    vb.className = `verdict-badge verdict-${rep.score.verdict}`;

    $('#hero-filename').textContent = rep.evidence.filename;
    $('#hero-sha256').textContent = 'sha256: ' + rep.evidence.sha256.slice(0, 16) + '…';
    $('#hero-subject').textContent = rep.headers.subject || '(no subject)';
    $('#hero-from').textContent = rep.headers.from
      ? (rep.headers.from.display_name ? `${rep.headers.from.display_name} <${rep.headers.from.address}>` : rep.headers.from.address)
      : '—';
    $('#hero-date').textContent = rep.headers.date || '—';
    $('#hero-auth').textContent = rep.auth.summary || '—';
    $('#score-summary').textContent = rep.score.summary || '';

    // Category breakdown pills
    const catOrder = ['headers', 'auth', 'hops', 'body', 'urls', 'attachments'];
    $('#category-bars').innerHTML = catOrder
      .map((c) => {
        const val = (rep.score.categories && rep.score.categories[c]) || 0;
        return `<div class="cat-chip ${val > 0 ? 'nonzero' : ''}"><span>${c}</span><b>+${val}</b></div>`;
      })
      .join('');

    // Tab counters
    $('#badge-findings').textContent = (rep.findings || []).length;
    $('#badge-hops').textContent = (rep.hops.hops || []).length;
    $('#badge-smug').textContent = ((rep.body.smuggling || []).length + (rep.body.embedded_payloads || []).length);
    $('#badge-urls').textContent = (rep.urls || []).length;
    $('#badge-att').textContent = (rep.attachments || []).length;

    renderFindings(rep);
    renderRecommendations(rep);
    renderManifest(rep);
    renderHopGraph(rep);
    renderIdentityAndAuth(rep);
    renderBodyTabs(rep);
    renderURLs(rep);
    renderAttachments(rep);
    renderIOCs(rep);
    loadTakedownPreview(item.id, state.takedownLang);
  }

  function renderFindings(rep) {
    const list = (rep.findings || []).filter((f) => state.sevFilter === 'ALL' || f.severity === state.sevFilter);
    const el = $('#findings-list');
    if (!list.length) {
      el.innerHTML = `<div class="finding-card"><div class="finding-head"><span class="sev-badge sev-INFO">CLEAN</span><span class="finding-title">No findings match this filter.</span></div></div>`;
      return;
    }
    el.innerHTML = list
      .map(
        (f) => `
      <div class="finding-card sev-border-${esc(f.severity)}">
        <div class="finding-head">
          <span class="sev-badge sev-${esc(f.severity)}">${esc(f.severity)}</span>
          <span class="tag">${esc(f.rule_id)}</span>
          <span class="tag">${esc(f.category)}</span>
          <span class="finding-title">${esc(f.title)}</span>
          <span class="finding-pts">+${f.points} pts</span>
        </div>
        <div class="finding-desc">${esc(f.description)}</div>
        ${f.evidence ? `<div class="finding-ev">${esc(f.evidence)}</div>` : ''}
      </div>`
      )
      .join('');
  }

  function renderRecommendations(rep) {
    $('#recommendations-list').innerHTML = (rep.recommendations || []).map((r) => `<li>${esc(r)}</li>`).join('');
  }

  function renderManifest(rep) {
    const ev = rep.evidence;
    $('#manifest-kv').innerHTML = `
      <dt>Filename</dt><dd>${esc(ev.filename)}</dd>
      <dt>Size</dt><dd>${ev.size_bytes} bytes (${ev.line_count} lines)</dd>
      <dt>Header/Body</dt><dd>${ev.header_size} B / ${ev.body_size} B</dd>
      <dt>SHA-256</dt><dd>${esc(ev.sha256)}</dd>
      <dt>SHA-1</dt><dd>${esc(ev.sha1)}</dd>
      <dt>MD5</dt><dd>${esc(ev.md5)}</dd>`;
  }

  function renderHopGraph(rep) {
    const hops = rep.hops.hops || [];
    const container = $('#hop-graph-container');
    const detailBox = $('#hop-detail-box');
    detailBox.classList.add('hidden');

    const summaryParts = [];
    if (rep.hops.origin_ip) summaryParts.push(`Origin IP: ${rep.hops.origin_ip}`);
    if (rep.hops.total_transit_seconds != null) summaryParts.push(`Total transit: ${rep.hops.total_transit_seconds.toFixed(0)}s`);
    if (rep.hops.has_clock_skew) summaryParts.push('⚠ CLOCK SKEW');
    if (rep.hops.has_unencrypted_hop) summaryParts.push('⚠ PLAINTEXT SMTP');
    $('#hop-meta-summary').textContent = summaryParts.join(' · ') || 'No Received hops';

    if (!hops.length) {
      container.innerHTML = `<div class="empty-hint">No SMTP Received headers found in this .eml artifact.</div>`;
      return;
    }

    const nodeW = 256;
    const nodeH = 104;
    const gapX = 76;
    const padX = 16;
    const padY = 18;
    const totalW = padX * 2 + hops.length * nodeW + (hops.length - 1) * gapX;
    const totalH = nodeH + padY * 2 + 12;

    const clipText = (str, max) => (str.length > max ? str.slice(0, max - 1) + '…' : str);

    let svgParts = [`<svg width="${totalW}" height="${totalH}" viewBox="0 0 ${totalW} ${totalH}" xmlns="http://www.w3.org/2000/svg">`];
    svgParts.push(`<defs><marker id="arr-ok" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8"/></marker><marker id="arr-warn" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 1 L 10 5 L 0 9 z" fill="#ef4444"/></marker></defs>`);

    hops.forEach((h, i) => {
      const x = padX + i * (nodeW + gapX);
      const y = padY;
      const borderColor = h.clock_skew ? '#ef4444' : (!h.tls && h.ip_scope === 'public' ? '#eab308' : '#2d3b54');
      const roleLabel = i === 0 ? 'HOP 1 · ORIGIN' : (i === hops.length - 1 ? `HOP ${h.index} · FINAL MX` : `HOP ${h.index} · RELAY`);
      const tlsText = h.tls ? 'TLS' : 'PLAIN';
      const tlsCol = h.tls ? '#22c55e' : '#eab308';
      const fromText = clipText(h.from_host || h.from_ip || 'unknown', 30);
      const byText = clipText(h.by_host || '—', 32);
      const ipText = h.from_ip ? `${h.from_ip} (${h.ip_scope})` : 'no IP recorded';

      // Draw edge to next hop
      if (i < hops.length - 1) {
        const next = hops[i + 1];
        const x1 = x + nodeW;
        const x2 = x + nodeW + gapX - 6;
        const midX = (x1 + x2) / 2;
        const midY = y + nodeH / 2;
        const edgeBad = next.clock_skew;
        const stroke = edgeBad ? '#ef4444' : '#38bdf8';
        const marker = edgeBad ? 'url(#arr-warn)' : 'url(#arr-ok)';
        const deltaLbl = next.delay_seconds != null ? `${next.delay_seconds >= 0 ? '+' : ''}${Math.round(next.delay_seconds)}s` : '—';
        svgParts.push(`<line x1="${x1}" y1="${midY}" x2="${x2}" y2="${midY}" stroke="${stroke}" stroke-width="2" marker-end="${marker}"/>`);
        svgParts.push(`<rect x="${midX - 28}" y="${midY - 22}" width="56" height="17" rx="4" fill="#141a26" stroke="${stroke}" stroke-width="1"/>`);
        svgParts.push(`<text x="${midX}" y="${midY - 10}" text-anchor="middle" fill="${edgeBad ? '#fca5a5' : '#bae6fd'}" font-family="ui-monospace, monospace" font-size="10" font-weight="700">${esc(deltaLbl)}</text>`);
        if (edgeBad) {
          svgParts.push(`<text x="${midX}" y="${midY + 15}" text-anchor="middle" fill="#f87171" font-family="ui-monospace, monospace" font-size="9.5" font-weight="700">SKEW!</text>`);
        }
      }

      svgParts.push(`<g class="hop-node" data-hop-idx="${i}" style="cursor:pointer">`);
      svgParts.push(`<rect x="${x}" y="${y}" width="${nodeW}" height="${nodeH}" rx="9" fill="#141a26" stroke="${borderColor}" stroke-width="1.6"/>`);
      svgParts.push(`<text x="${x + 12}" y="${y + 20}" fill="#93a1b8" font-family="ui-monospace, monospace" font-size="10" font-weight="700">${esc(roleLabel)}</text>`);
      svgParts.push(`<rect x="${x + nodeW - 52}" y="${y + 8}" width="42" height="16" rx="4" fill="rgba(255,255,255,0.04)" stroke="${tlsCol}" stroke-width="1"/>`);
      svgParts.push(`<text x="${x + nodeW - 31}" y="${y + 19}" text-anchor="middle" fill="${tlsCol}" font-family="ui-monospace, monospace" font-size="9.5" font-weight="700">${tlsText}</text>`);
      svgParts.push(`<text x="${x + 12}" y="${y + 42}" fill="#e6ecf5" font-family="ui-monospace, monospace" font-size="11.5" font-weight="700">${esc(fromText)}</text>`);
      svgParts.push(`<text x="${x + 12}" y="${y + 60}" fill="#38bdf8" font-family="ui-monospace, monospace" font-size="10.5">${esc(ipText)}</text>`);
      svgParts.push(`<text x="${x + 12}" y="${y + 78}" fill="#93a1b8" font-family="ui-monospace, monospace" font-size="10">by ${esc(byText)}</text>`);
      svgParts.push(`<text x="${x + 12}" y="${y + 94}" fill="#64748b" font-family="ui-monospace, monospace" font-size="9.5">${esc(h.protocol || 'SMTP')} · click for raw</text>`);
      svgParts.push(`</g>`);
    });

    svgParts.push('</svg>');
    container.innerHTML = svgParts.join('');

    container.querySelectorAll('.hop-node').forEach((node) => {
      node.addEventListener('click', () => {
        const h = hops[Number(node.dataset.hopIdx)];
        detailBox.classList.remove('hidden');
        detailBox.innerHTML = `
          <div style="display:flex;justify-content:space-between;margin-bottom:6px">
            <strong>Hop #${h.index} Raw Received Header</strong>
            <span class="mono muted">${esc(h.timestamp_raw || '')}</span>
          </div>
          <div class="finding-ev">${esc(h.raw)}</div>
          ${(h.notes && h.notes.length) ? `<div style="margin-top:8px;color:#fca5a5">${h.notes.map(esc).join(' · ')}</div>` : ''}
        `;
      });
    });
  }

  function renderIdentityAndAuth(rep) {
    const id = rep.identity;
    const badge = (bad, okLbl, badLbl) => `<span class="tag ${bad ? 'tag-danger' : 'tag-ok'}">${bad ? badLbl : okLbl}</span>`;

    $('#identity-matrix').innerHTML = `
      <div class="id-row"><span>From Domain</span><span class="mono">${esc(id.from_domain || '—')} ${id.from_punycode_decoded ? `<span class="tag tag-danger">IDN: ${esc(id.from_punycode_decoded)}</span>` : ''}</span></div>
      <div class="id-row"><span>Return-Path</span><span class="mono">${esc(id.return_path_domain || '—')} ${id.return_path_domain ? badge(id.return_path_mismatch, 'ALIGNED', 'MISMATCH') : ''}</span></div>
      <div class="id-row"><span>Reply-To</span><span class="mono">${esc((id.reply_to_domains || []).join(', ') || '—')} ${id.reply_to_freemail ? '<span class="tag tag-danger">FREEMAIL BEC</span>' : (id.reply_to_mismatch ? '<span class="tag tag-warn">MISMATCH</span>' : '')}</span></div>
      <div class="id-row"><span>Message-ID Domain</span><span class="mono">${esc(rep.headers.message_domain || '—')} ${rep.headers.message_domain ? badge(id.message_id_domain_mismatch, 'ALIGNED', 'DIFFERS') : ''}</span></div>
      <div class="id-row"><span>Display Name Spoof</span><span>${badge(id.display_name_spoof, 'NONE', id.display_name_brand_impersonated || id.display_name_embedded_email || 'SPOOFED')}</span></div>
      <div class="id-row"><span>DKIM Domains (d=)</span><span class="mono">${esc((id.dkim_domains || []).join(', ') || '—')}</span></div>
    `;

    const auth = rep.auth;
    const cls = (st) => (!st ? 'muted' : st === 'pass' ? 'status-pass' : (st === 'fail' ? 'status-fail' : 'status-warn'));
    const spfSt = auth.spf ? auth.spf.status : 'missing';
    const dkimSt = (auth.dkim && auth.dkim.length) ? auth.dkim[0].status : (auth.dkim_signatures && auth.dkim_signatures.length ? (auth.dkim_signatures[0].body_hash_match ? 'bh=ok' : 'bh=fail') : 'missing');
    const dmarcSt = auth.dmarc ? auth.dmarc.status : 'missing';

    let html = `
      <div class="auth-grid">
        <div class="auth-tile"><div class="auth-mech">SPF</div><div class="auth-status ${cls(spfSt)}">${esc(spfSt)}</div></div>
        <div class="auth-tile"><div class="auth-mech">DKIM</div><div class="auth-status ${cls(dkimSt === 'bh=ok' ? 'pass' : dkimSt === 'bh=fail' ? 'fail' : dkimSt)}">${esc(dkimSt)}</div></div>
        <div class="auth-tile"><div class="auth-mech">DMARC</div><div class="auth-status ${cls(dmarcSt)}">${esc(dmarcSt)}</div></div>
      </div>`;

    if (auth.dkim_signatures && auth.dkim_signatures.length) {
      html += auth.dkim_signatures
        .map(
          (d) => `
        <div class="dkim-card">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">
            <strong>DKIM-Signature #${d.index}</strong>
            <span class="tag">d=${esc(d.domain)}</span>
            <span class="tag">s=${esc(d.selector)}</span>
            <span class="tag">${esc(d.algorithm)} (${esc(d.canonicalization)})</span>
            <span class="tag ${d.body_hash_match ? 'tag-ok' : 'tag-danger'}">${d.body_hash_match ? 'OFFLINE bh= MATCH' : 'OFFLINE bh= MISMATCH'}</span>
          </div>
          <div class="mono" style="font-size:11px;color:#93a1b8;word-break:break-all">
            declared bh= ${esc(d.declared_body_hash)}<br/>
            computed bh= ${esc(d.computed_body_hash)}
          </div>
          <div style="margin-top:5px;font-size:11.5px;color:#93a1b8">${esc(d.note)}</div>
        </div>`
        )
        .join('');
    } else {
      html += `<div class="empty-hint">No DKIM-Signature headers present for offline RFC 6376 bh= verification.</div>`;
    }
    $('#auth-cards').innerHTML = html;
  }

  function renderBodyTabs(rep) {
    const b = rep.body;
    const blockedMsg = b.blocked_remote_count > 0
      ? `Sandboxed offline iframe (scripts disabled · <strong>${b.blocked_remote_count} remote tracking/resource fetch(es) blocked</strong> from: <span class="mono">${esc((b.blocked_remote_hosts || []).join(', '))}</span>)`
      : `Sandboxed offline iframe (scripts disabled · zero network requests).`;
    $('#sandbox-banner').innerHTML = blockedMsg;

    const frame = $('#safe-preview-frame');
    if (b.has_html) {
      frame.srcdoc = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">` + b.sanitized_html;
    } else {
      frame.srcdoc = `<pre style="font-family:monospace;padding:16px;white-space:pre-wrap;color:#111">${esc(b.plain_text || '(empty body)')}</pre>`;
    }

    // Smuggling & Stealth subpanel
    let smugHTML = '';
    if (b.smuggling && b.smuggling.length) {
      smugHTML += `<div class="card"><div class="card-header"><h3>HTML Smuggling &amp; Active Content Indicators (${b.smuggling.length})</h3></div>` +
        b.smuggling.map((s) => `
          <div class="finding-card sev-border-${esc(s.severity)}" style="margin-bottom:8px">
            <div class="finding-head"><span class="sev-badge sev-${esc(s.severity)}">${esc(s.severity)}</span><span class="tag">${esc(s.type)}</span></div>
            <div class="finding-desc">${esc(s.detail)}</div>
            <div class="finding-ev">${esc(s.evidence)}</div>
          </div>`).join('') + `</div>`;
    }
    if (b.embedded_payloads && b.embedded_payloads.length) {
      smugHTML += `<div class="card"><div class="card-header"><h3>Decoded Embedded data: URI Payloads (${b.embedded_payloads.length})</h3></div>` +
        b.embedded_payloads.map((p) => `
          <div class="att-card">
            <div class="att-head">
              <span class="tag ${p.suspicious ? 'tag-danger' : 'tag-ok'}">${p.suspicious ? 'SUSPICIOUS' : 'BENIGN'}</span>
              <span class="tag">${esc(p.mime_type)}</span>
              <span class="tag">${esc(p.detected_magic)}</span>
              <span class="mono muted">${p.size_bytes} B</span>
            </div>
            <div class="mono" style="font-size:11px;color:#93a1b8">sha256=${esc(p.sha256)}</div>
            ${p.reasons && p.reasons.length ? `<ul class="reason-list">${p.reasons.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
          </div>`).join('') + `</div>`;
    }
    smugHTML += `
      <div class="card">
        <div class="card-header"><h3>Stealth, Forms &amp; Cloaking Telemetry</h3></div>
        <div class="id-row"><span>Zero-width stealth characters</span><span class="mono">${b.zero_width_count}</span></div>
        <div class="id-row"><span>BiDi override characters (RLO/LRO)</span><span class="mono">${b.bidi_override_count}</span></div>
        <div class="id-row"><span>Embedded &lt;input type="password"&gt;</span><span class="mono">${b.password_input_count}</span></div>
        <div class="id-row"><span>HTML Form actions</span><span class="mono">${esc((b.form_actions || []).join(', ') || 'none')}</span></div>
        <div class="id-row"><span>Urgency / social-engineering cues</span><span>${esc((b.urgency_signals || []).join(' · ') || 'none')}</span></div>
        ${(b.hidden_text_snippets && b.hidden_text_snippets.length) ? `<div style="margin-top:10px"><strong>Hidden CSS Cloaking Snippets:</strong>${b.hidden_text_snippets.map((h) => `<div class="finding-ev" style="margin-top:6px">${esc(h)}</div>`).join('')}</div>` : ''}
      </div>`;
    $('#smuggling-content').innerHTML = smugHTML;

    $('#raw-html-viewer').textContent = b.raw_html || '(no HTML body part)';
    $('#plain-text-viewer').textContent = b.plain_text || '(no plain-text body part)';
    $('#header-search').value = '';
    renderAllHeaders(rep, '');
  }

  function renderAllHeaders(rep, filter) {
    const q = (filter || '').toLowerCase();
    const rows = (rep.headers.all_headers || []).filter((h) => !q || h.name.toLowerCase().includes(q) || h.value.toLowerCase().includes(q));
    $('#all-headers-table tbody').innerHTML = rows
      .map((h) => `<tr><td style="width:210px;color:#38bdf8">${esc(h.name)}</td><td>${esc(h.value)}</td></tr>`)
      .join('');
  }

  function renderURLs(rep) {
    const urls = rep.urls || [];
    const el = $('#urls-container');
    if (!urls.length) {
      el.innerHTML = `<div class="empty-hint">${esc(i18n[state.lang].no_urls)}</div>`;
      return;
    }
    el.innerHTML = urls
      .map(
        (u) => `
      <div class="url-card">
        <div class="url-head">
          <span class="sev-badge sev-${esc(u.severity)}">${esc(u.severity)} · ${u.risk_score}</span>
          <span class="tag">${esc(u.source)}</span>
          ${u.is_punycode ? `<span class="tag tag-danger">IDN: ${esc(u.decoded_host)}</span>` : ''}
          ${u.is_homoglyph ? `<span class="tag tag-danger">HOMOGLYPH</span>` : ''}
          ${u.anchor_mismatch ? `<span class="tag tag-danger">ANCHOR MISMATCH</span>` : ''}
          ${u.impersonated_brand ? `<span class="tag tag-warn">BRAND: ${esc(u.impersonated_brand)}</span>` : ''}
          ${u.is_ip_address ? `<span class="tag tag-danger">RAW IP</span>` : ''}
          ${u.has_userinfo_at ? `<span class="tag tag-danger">@ SPOOF</span>` : ''}
          ${u.is_shortener ? `<span class="tag tag-warn">SHORTENER</span>` : ''}
        </div>
        <div class="url-defanged mono">${esc(u.defanged)}</div>
        ${u.anchor_text ? `<div class="muted" style="font-size:12px;margin-top:4px">Visible anchor text: <span class="mono">${esc(u.anchor_text)}</span></div>` : ''}
        ${u.redirect_target ? `<div class="muted" style="font-size:12px;margin-top:4px">Unwrapped redirect target: <span class="mono" style="color:#fca5a5">${esc(u.redirect_target)}</span></div>` : ''}
        ${(u.reasons && u.reasons.length) ? `<ul class="reason-list">${u.reasons.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
      </div>`
      )
      .join('');
  }

  function renderAttachments(rep) {
    const atts = rep.attachments || [];
    const el = $('#attachments-container');
    if (!atts.length) {
      el.innerHTML = `<div class="card"><div class="empty-hint">${esc(i18n[state.lang].no_attachments)}</div></div>`;
      return;
    }
    el.innerHTML = atts
      .map((a) => {
        const entPct = Math.min(100, Math.round((a.entropy / 8) * 100));
        const entColor = a.entropy > 7.5 ? '#ef4444' : (a.entropy > 6.5 ? '#eab308' : '#38bdf8');
        let membersHTML = '';
        if (a.archive_members && a.archive_members.length) {
          membersHTML = `
            <div style="margin-top:10px">
              <strong style="font-size:12px">Archive / OOXML Structure (${a.archive_members.length} entries)</strong>
              <div class="table-scroll" style="margin-top:6px">
                <table class="data-table mono">
                  <thead><tr><th>Member</th><th>Size</th><th>Flags</th><th>Note</th></tr></thead>
                  <tbody>${a.archive_members
                    .map(
                      (m) => `
                    <tr>
                      <td>${esc(m.name)}</td>
                      <td>${m.uncompressed_size} B</td>
                      <td>${m.encrypted ? '<span class="tag tag-danger">ENCRYPTED</span>' : ''} ${m.dangerous ? '<span class="tag tag-danger">HIGH RISK</span>' : '<span class="tag">ok</span>'}</td>
                      <td>${esc(m.note || '')}</td>
                    </tr>`
                    )
                    .join('')}</tbody>
                </table>
              </div>
            </div>`;
        }
        return `
        <div class="att-card">
          <div class="att-head">
            <span class="sev-badge sev-${esc(a.severity)}">${esc(a.severity)} · ${a.risk_score}</span>
            <strong class="mono" style="font-size:14px">${esc(a.filename)}</strong>
            <span class="tag">${esc(a.detected_magic)}</span>
            <span class="tag">${a.size_bytes} B</span>
            ${a.magic_mismatch ? '<span class="tag tag-danger">MAGIC MISMATCH</span>' : ''}
            ${a.double_extension ? '<span class="tag tag-danger">DOUBLE EXT</span>' : ''}
            ${a.has_rlo_filename ? '<span class="tag tag-danger">RLO SPOOF</span>' : ''}
            ${a.has_macros ? '<span class="tag tag-danger">VBA MACROS</span>' : ''}
            ${a.has_external_template ? '<span class="tag tag-danger">EXTERNAL TEMPLATE</span>' : ''}
            ${a.has_encrypted_archive ? '<span class="tag tag-warn">ENCRYPTED ZIP</span>' : ''}
          </div>
          <div class="entropy-bar-wrap">
            <span>Shannon Entropy: <strong>${a.entropy.toFixed(2)}</strong> / 8.00</span>
            <div class="entropy-track"><div class="entropy-fill" style="width:${entPct}%;background:${entColor}"></div></div>
          </div>
          <div class="mono" style="font-size:11px;color:#93a1b8;word-break:break-all">
            SHA-256: ${esc(a.sha256)}<br/>
            SHA-1:   ${esc(a.sha1)} &nbsp;·&nbsp; MD5: ${esc(a.md5)}
          </div>
          ${(a.pdf_indicators && a.pdf_indicators.length) ? `<div style="margin-top:8px">PDF Tags: ${a.pdf_indicators.map((p) => `<span class="tag tag-danger">${esc(p)}</span>`).join(' ')}</div>` : ''}
          ${(a.script_indicators && a.script_indicators.length) ? `<div style="margin-top:8px">Execution Indicators: ${a.script_indicators.map((p) => `<span class="tag tag-danger">${esc(p)}</span>`).join(' ')}</div>` : ''}
          ${(a.html_smuggling && a.html_smuggling.length) ? `<div style="margin-top:8px">HTML Smuggling: ${a.html_smuggling.map((s) => `<span class="tag tag-danger">${esc(s.type)}</span>`).join(' ')}</div>` : ''}
          ${(a.reasons && a.reasons.length) ? `<ul class="reason-list">${a.reasons.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
          ${membersHTML}
        </div>`;
      })
      .join('');
  }

  function renderIOCs(rep) {
    const i = rep.iocs;
    const lines = [];
    if (i.defanged_ips && i.defanged_ips.length) {
      lines.push('# Public IPs (Defanged)', ...i.defanged_ips, '');
    }
    if (i.defanged_domains && i.defanged_domains.length) {
      lines.push('# Domains (Defanged)', ...i.defanged_domains, '');
    }
    if (i.defanged_urls && i.defanged_urls.length) {
      lines.push('# URLs (Defanged)', ...i.defanged_urls, '');
    }
    if (i.emails && i.emails.length) {
      lines.push('# Email Addresses', ...i.emails, '');
    }
    if (i.file_hashes_sha256 && i.file_hashes_sha256.length) {
      lines.push('# Attachment / Payload SHA-256', ...i.file_hashes_sha256, '');
    }
    $('#iocs-viewer').textContent = lines.join('\n') || '(no IOCs extracted)';
  }

  async function loadTakedownPreview(id, lang) {
    try {
      const txt = await fetch(`/api/export/${encodeURIComponent(id)}/takedown?lang=${encodeURIComponent(lang)}`).then((r) => r.text());
      $('#takedown-viewer').textContent = txt;
    } catch {
      $('#takedown-viewer').textContent = 'Failed to load takedown draft.';
    }
  }

  init();
})();
