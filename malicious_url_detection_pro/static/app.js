const form = document.getElementById('scan-form');
const input = document.getElementById('url-input');
const btn = document.getElementById('scan-btn');
const errorBox = document.getElementById('error-box');
const results = document.getElementById('results');
let latestReport = null;

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorBox.classList.add('hidden');
  results.classList.add('hidden');
  btn.disabled = true;
  btn.querySelector('.btn-text').textContent = 'Scanning…';
  try {
    const response = await fetch('/api/scan', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url: input.value})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Scan failed.');
    latestReport = data;
    renderReport(data);
    results.classList.remove('hidden');
    results.scrollIntoView({behavior: 'smooth', block: 'start'});
  } catch (error) {
    errorBox.textContent = error.message || 'Unable to scan this URL.';
    errorBox.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.querySelector('.btn-text').textContent = 'Scan URL';
  }
});

function renderReport(d) {
  const score = d.risk_score;
  const color = d.verdict === 'dangerous' ? 'var(--red)' :
    d.verdict === 'suspicious' ? 'var(--amber)' : 'var(--cyan)';
  document.getElementById('score').textContent = score;
  document.getElementById('score-ring').style.background =
    `conic-gradient(${color} ${score * 3.6}deg, #263242 ${score * 3.6}deg)`;
  document.getElementById('meter-fill').style.width = `${score}%`;
  document.getElementById('meter-fill').style.background = color;
  document.getElementById('verdict').textContent = d.verdict_label;
  document.getElementById('verdict').style.color = color;
  document.getElementById('host').textContent = d.hostname;
  document.getElementById('scan-scheme').textContent = d.scheme.toUpperCase();
  document.getElementById('signal-count').textContent = `${d.findings.length} SIGNAL${d.findings.length === 1 ? '' : 'S'}`;
  document.getElementById('normalized').textContent = d.normalized_url;
  document.getElementById('ascii-host').textContent = d.ascii_hostname;
  document.getElementById('hash').textContent = d.url_sha256;
  document.getElementById('disclaimer').textContent = d.disclaimer;
  const rep = d.reputation;
  let repText = rep.message || 'Reputation check unavailable.';
  if (rep.status === 'not_configured') repText += ' Configure GOOGLE_SAFE_BROWSING_API_KEY to enable live reputation checks.';
  if (rep.status === 'malicious') repText = 'THREAT MATCH: ' + rep.message;
  document.getElementById('reputation').textContent = 'REPUTATION CHECK · ' + repText;
  const list = document.getElementById('findings');
  list.replaceChildren();
  d.findings.forEach(item => {
    const card = document.createElement('div');
    card.className = `finding ${item.severity}`;
    const bullet = document.createElement('span'); bullet.className = 'bullet';
    const body = document.createElement('div');
    const title = document.createElement('h4'); title.textContent = item.title;
    const detail = document.createElement('p'); detail.textContent = item.detail;
    body.append(title, detail); card.append(bullet, body); list.append(card);
  });
}

document.getElementById('copy-btn').addEventListener('click', async () => {
  if (!latestReport) return;
  const report = [
    'LinkSentinel URL Analysis',
    `URL: ${latestReport.normalized_url}`,
    `Verdict: ${latestReport.verdict_label}`,
    `Risk score: ${latestReport.risk_score}/100`,
    `Hostname: ${latestReport.hostname}`,
    'Signals:',
    ...latestReport.findings.map(f => `- ${f.title}: ${f.detail}`),
    `Reputation: ${latestReport.reputation.message}`,
    latestReport.disclaimer
  ].join('\n');
  const button = document.getElementById('copy-btn');
  try {
    await navigator.clipboard.writeText(report);
    button.textContent = 'Copied ✓';
    setTimeout(() => button.textContent = 'Copy report ↗', 1600);
  } catch {
    button.textContent = 'Clipboard unavailable';
  }
});
