const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: {"Content-Type": "application/json", ...(options.headers || {})},
    ...options,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || data.message || `HTTP ${res.status}`);
  return data;
}

async function refresh() {
  const status = await api('/api/status');
  $('modelBadge').textContent = `${status.model} · top-k ${status.top_k}`;
  const kb = await api('/api/knowledge');
  $('documents').innerHTML = kb.documents.map(d => `
    <article class="doc">
      <strong>${escapeHtml(d.title)}</strong>
      <span>${escapeHtml(d.status)} · priority ${d.priority}</span>
      <small>${escapeHtml(d.id)} · ${escapeHtml(d.source)}</small>
    </article>`).join('');
}

$('askBtn').onclick = async () => {
  try {
    const data = await api('/api/rag/query', {
      method: 'POST',
      body: JSON.stringify({query: $('query').value})
    });
    $('answer').textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    $('answer').textContent = e.message;
  }
};

$('importBtn').onclick = async () => {
  try {
    const data = await api('/api/knowledge/import', {
      method: 'POST',
      body: JSON.stringify({
        title: $('title').value,
        content: $('content').value,
        metadata: {source: $('source').value}
      })
    });
    $('importResult').textContent = JSON.stringify(data, null, 2);
    await refresh();
  } catch (e) {
    $('importResult').textContent = e.message;
  }
};

function escapeHtml(s) {
  return String(s).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}

refresh().catch(e => $('modelBadge').textContent = e.message);
