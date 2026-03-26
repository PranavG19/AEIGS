/// Embedded HTML dashboard served as a single-page application.
/// Uses D3.js v7 from CDN for force-directed graph rendering.
pub const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AEGIS — Attack Graph Dashboard</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
:root {
  --bg-primary: #0a0e17;
  --bg-secondary: #111827;
  --bg-card: #1a2332;
  --text-primary: #e2e8f0;
  --text-secondary: #94a3b8;
  --accent-blue: #3b82f6;
  --accent-red: #ef4444;
  --accent-orange: #f97316;
  --accent-yellow: #eab308;
  --accent-green: #22c55e;
  --border: #1e293b;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  background: var(--bg-primary);
  color: var(--text-primary);
  font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
  overflow: hidden;
  height: 100vh;
}

.layout {
  display: grid;
  grid-template-columns: 280px 1fr 320px;
  grid-template-rows: 1fr 180px;
  height: 100vh;
  gap: 1px;
  background: var(--border);
}

/* Left sidebar */
.sidebar-left {
  background: var(--bg-secondary);
  padding: 16px;
  overflow-y: auto;
  grid-row: 1 / 3;
}

.sidebar-left h2 {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  color: var(--text-secondary);
  margin-bottom: 12px;
}

.logo {
  font-size: 20px;
  font-weight: 700;
  color: var(--accent-blue);
  margin-bottom: 24px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.logo .dot { color: var(--accent-red); }

.stat-card {
  background: var(--bg-card);
  border-radius: 8px;
  padding: 12px;
  margin-bottom: 8px;
}

.stat-label {
  font-size: 10px;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 1px;
}

.stat-value {
  font-size: 24px;
  font-weight: 700;
  margin-top: 4px;
}

.phase-indicator {
  background: var(--bg-card);
  border-radius: 8px;
  padding: 12px;
  margin-bottom: 8px;
}

.phase-name {
  font-size: 13px;
  color: var(--accent-blue);
  font-weight: 600;
}

.progress-bar {
  height: 4px;
  background: var(--bg-primary);
  border-radius: 2px;
  margin-top: 8px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: var(--accent-blue);
  border-radius: 2px;
  transition: width 0.5s ease;
  width: 0%;
}

.legend { margin-top: 16px; }
.legend-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  margin-bottom: 6px;
  color: var(--text-secondary);
}

.legend-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}

/* Main graph area */
.graph-container {
  background: var(--bg-primary);
  position: relative;
}

.graph-container svg {
  width: 100%;
  height: 100%;
}

/* Right sidebar */
.sidebar-right {
  background: var(--bg-secondary);
  padding: 16px;
  overflow-y: auto;
  grid-row: 1 / 3;
}

.finding-card {
  background: var(--bg-card);
  border-radius: 8px;
  padding: 10px 12px;
  margin-bottom: 6px;
  border-left: 3px solid var(--text-secondary);
  cursor: pointer;
  transition: background 0.15s;
}

.finding-card:hover { background: #243044; }
.finding-card.critical { border-left-color: var(--accent-red); }
.finding-card.high { border-left-color: var(--accent-orange); }
.finding-card.medium { border-left-color: var(--accent-yellow); }
.finding-card.low { border-left-color: var(--accent-green); }

.finding-class {
  font-size: 12px;
  font-weight: 600;
}

.finding-endpoint {
  font-size: 11px;
  color: var(--text-secondary);
  margin-top: 2px;
  word-break: break-all;
}

.finding-severity {
  display: inline-block;
  font-size: 9px;
  text-transform: uppercase;
  letter-spacing: 1px;
  padding: 2px 6px;
  border-radius: 3px;
  margin-top: 4px;
  font-weight: 700;
}

.finding-severity.critical { background: rgba(239,68,68,0.2); color: var(--accent-red); }
.finding-severity.high { background: rgba(249,115,22,0.2); color: var(--accent-orange); }
.finding-severity.medium { background: rgba(234,179,8,0.2); color: var(--accent-yellow); }
.finding-severity.low { background: rgba(34,197,94,0.2); color: var(--accent-green); }

/* Bottom log panel */
.log-panel {
  background: var(--bg-secondary);
  padding: 12px 16px;
  overflow-y: auto;
  font-size: 11px;
  line-height: 1.6;
}

.log-line { color: var(--text-secondary); }
.log-line .timestamp { color: #475569; margin-right: 8px; }
.log-line.info .msg { color: var(--accent-blue); }
.log-line.warn .msg { color: var(--accent-yellow); }
.log-line.error .msg { color: var(--accent-red); }
.log-line.success .msg { color: var(--accent-green); }

/* Modal */
.modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.7);
  z-index: 100;
  justify-content: center;
  align-items: center;
}

.modal-overlay.active { display: flex; }

.modal {
  background: var(--bg-card);
  border-radius: 12px;
  padding: 24px;
  max-width: 640px;
  width: 90%;
  max-height: 80vh;
  overflow-y: auto;
  border: 1px solid var(--border);
}

.modal h3 {
  font-size: 16px;
  margin-bottom: 16px;
}

.modal pre {
  background: var(--bg-primary);
  padding: 12px;
  border-radius: 6px;
  font-size: 11px;
  overflow-x: auto;
  margin-top: 8px;
}

.modal-close {
  float: right;
  background: none;
  border: none;
  color: var(--text-secondary);
  font-size: 20px;
  cursor: pointer;
}

/* Keyboard hints */
.kbd-hints {
  position: absolute;
  bottom: 8px;
  right: 8px;
  font-size: 10px;
  color: #334155;
}

kbd {
  background: var(--bg-card);
  padding: 1px 5px;
  border-radius: 3px;
  border: 1px solid var(--border);
}

/* Pulse animation for new vulnerability nodes */
@keyframes pulse-red {
  0% { filter: drop-shadow(0 0 4px rgba(239,68,68,0.8)); }
  50% { filter: drop-shadow(0 0 12px rgba(239,68,68,1)); }
  100% { filter: drop-shadow(0 0 4px rgba(239,68,68,0.8)); }
}
.node-pulse { animation: pulse-red 1.5s ease-in-out infinite; }

/* Edge animation */
@keyframes dash-flow {
  to { stroke-dashoffset: -20; }
}
.edge-animated {
  stroke-dasharray: 6 4;
  animation: dash-flow 1s linear infinite;
}
</style>
</head>
<body>

<div class="layout">
  <!-- Left Sidebar -->
  <div class="sidebar-left">
    <div class="logo">⬡ AEGIS<span class="dot">.</span></div>

    <div class="phase-indicator">
      <div class="stat-label">Current Phase</div>
      <div class="phase-name" id="phase-name">Idle</div>
      <div class="progress-bar"><div class="progress-fill" id="progress-fill"></div></div>
    </div>

    <div class="stat-card">
      <div class="stat-label">Findings</div>
      <div class="stat-value" id="stat-findings" style="color:var(--accent-red)">0</div>
    </div>

    <div class="stat-card">
      <div class="stat-label">Endpoints</div>
      <div class="stat-value" id="stat-endpoints" style="color:var(--accent-blue)">0</div>
    </div>

    <div class="stat-card">
      <div class="stat-label">Risk Score</div>
      <div class="stat-value" id="stat-risk" style="color:var(--accent-orange)">—</div>
    </div>

    <div class="stat-card">
      <div class="stat-label">Duration</div>
      <div class="stat-value" id="stat-duration" style="color:var(--text-secondary);font-size:18px">0s</div>
    </div>

    <div class="legend">
      <h2>Legend</h2>
      <div class="legend-item"><div class="legend-dot" style="background:var(--accent-blue)"></div> Endpoint</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--accent-red)"></div> Vulnerability (Critical)</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--accent-orange)"></div> Vulnerability (High)</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--accent-yellow)"></div> Vulnerability (Medium)</div>
      <div class="legend-item"><div class="legend-dot" style="background:var(--accent-green);clip-path:polygon(50% 0,100% 50%,50% 100%,0 50%)"></div> Asset</div>
    </div>
  </div>

  <!-- Main Graph -->
  <div class="graph-container" id="graph-container">
    <svg id="graph-svg"></svg>
    <div class="kbd-hints">
      <kbd>Space</kbd> pause &nbsp; <kbd>R</kbd> reset &nbsp; <kbd>F</kbd> fullscreen &nbsp; <kbd>E</kbd> export SVG
    </div>
  </div>

  <!-- Right Sidebar -->
  <div class="sidebar-right">
    <h2>Findings</h2>
    <div id="findings-list"></div>
  </div>

  <!-- Bottom Log -->
  <div class="log-panel" id="log-panel"></div>
</div>

<!-- Detail Modal -->
<div class="modal-overlay" id="modal-overlay">
  <div class="modal">
    <button class="modal-close" onclick="closeModal()">&times;</button>
    <h3 id="modal-title">Finding Details</h3>
    <div id="modal-body"></div>
  </div>
</div>

<script>
// ========== STATE ==========
const nodes = new Map();
const edges = [];
let simulation;
let svgGroup;
let isPaused = false;

// ========== D3 SETUP ==========
const svg = d3.select('#graph-svg');
const container = document.getElementById('graph-container');
const width = container.clientWidth;
const height = container.clientHeight;

svg.attr('viewBox', [0, 0, width, height]);

svgGroup = svg.append('g');

// Zoom
const zoom = d3.zoom()
  .scaleExtent([0.2, 5])
  .on('zoom', (e) => svgGroup.attr('transform', e.transform));
svg.call(zoom);

const linkGroup = svgGroup.append('g').attr('class', 'links');
const nodeGroup = svgGroup.append('g').attr('class', 'nodes');
const labelGroup = svgGroup.append('g').attr('class', 'labels');

simulation = d3.forceSimulation()
  .force('link', d3.forceLink().id(d => d.id).distance(120))
  .force('charge', d3.forceManyBody().strength(-300))
  .force('center', d3.forceCenter(width / 2, height / 2))
  .force('collision', d3.forceCollide().radius(30))
  .on('tick', ticked);

function ticked() {
  linkGroup.selectAll('line')
    .attr('x1', d => d.source.x)
    .attr('y1', d => d.source.y)
    .attr('x2', d => d.target.x)
    .attr('y2', d => d.target.y);

  nodeGroup.selectAll('.node')
    .attr('transform', d => `translate(${d.x},${d.y})`);

  labelGroup.selectAll('text')
    .attr('x', d => d.x)
    .attr('y', d => d.y + 24);
}

function severityColor(sev) {
  if (!sev) return '#3b82f6';
  switch(sev.toLowerCase()) {
    case 'critical': return '#ef4444';
    case 'high': return '#f97316';
    case 'medium': return '#eab308';
    case 'low': return '#22c55e';
    default: return '#3b82f6';
  }
}

function nodeRadius(d) {
  if (d.node_type === 'vulnerability') return 14;
  if (d.node_type === 'asset') return 12;
  return 10;
}

function edgeColor(label) {
  switch(label) {
    case 'exploits': return '#ef4444';
    case 'chains_to': return '#f97316';
    case 'exposes': return '#eab308';
    default: return '#334155';
  }
}

function updateGraph() {
  const nodeData = Array.from(nodes.values());
  const linkData = edges.filter(e =>
    nodes.has(e.source?.id || e.source) && nodes.has(e.target?.id || e.target)
  );

  // Links
  const link = linkGroup.selectAll('line').data(linkData, d => `${d.source?.id||d.source}-${d.target?.id||d.target}`);
  link.exit().remove();
  link.enter().append('line')
    .attr('stroke', d => edgeColor(d.label))
    .attr('stroke-width', 1.5)
    .attr('stroke-opacity', 0.6)
    .classed('edge-animated', true);

  // Nodes
  const node = nodeGroup.selectAll('.node').data(nodeData, d => d.id);
  node.exit().remove();
  const nodeEnter = node.enter().append('g').attr('class', 'node').call(drag(simulation));

  nodeEnter.each(function(d) {
    const g = d3.select(this);
    if (d.node_type === 'asset') {
      g.append('polygon')
        .attr('points', '-12,0 0,-12 12,0 0,12')
        .attr('fill', '#22c55e')
        .attr('fill-opacity', 0.8)
        .attr('stroke', '#22c55e')
        .attr('stroke-width', 1.5);
    } else {
      g.append('circle')
        .attr('r', nodeRadius(d))
        .attr('fill', severityColor(d.severity))
        .attr('fill-opacity', 0.8)
        .attr('stroke', severityColor(d.severity))
        .attr('stroke-width', 1.5);
    }
    g.on('click', (event, d) => showNodeDetail(d));
  });

  // Labels
  const label = labelGroup.selectAll('text').data(nodeData, d => d.id);
  label.exit().remove();
  label.enter().append('text')
    .attr('text-anchor', 'middle')
    .attr('font-size', '10px')
    .attr('fill', '#94a3b8')
    .text(d => d.label.length > 20 ? d.label.slice(0,18) + '…' : d.label);

  simulation.nodes(nodeData);
  simulation.force('link').links(linkData);
  simulation.alpha(0.3).restart();
}

function drag(sim) {
  return d3.drag()
    .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
    .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
    .on('end', (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; });
}

// ========== EVENT HANDLERS ==========
function handleEvent(evt) {
  switch(evt.type) {
    case 'NodeAdded':
      if (!nodes.has(evt.id)) {
        nodes.set(evt.id, {
          id: evt.id, node_type: evt.node_type, label: evt.label,
          severity: evt.severity, status: 'discovered', data: evt.data || {},
          x: width/2 + (Math.random()-0.5)*100,
          y: height/2 + (Math.random()-0.5)*100
        });
        if (evt.node_type === 'endpoint') updateStat('stat-endpoints', nodes.size);
        updateGraph();
      }
      break;

    case 'EdgeAdded':
      edges.push({ source: evt.source, target: evt.target, label: evt.label });
      updateGraph();
      break;

    case 'NodeUpdated': {
      const n = nodes.get(evt.id);
      if (n) {
        n.status = evt.status;
        if (evt.confidence != null) n.confidence = evt.confidence;
        if (evt.status === 'vulnerable') {
          nodeGroup.selectAll('.node')
            .filter(d => d.id === evt.id)
            .classed('node-pulse', true);
        }
      }
      break;
    }

    case 'FindingConfirmed':
      addFinding(evt);
      break;

    case 'PhaseChanged':
      document.getElementById('phase-name').textContent = evt.phase;
      document.getElementById('progress-fill').style.width = evt.progress_pct + '%';
      break;

    case 'ScanComplete':
      document.getElementById('phase-name').textContent = 'Complete';
      document.getElementById('progress-fill').style.width = '100%';
      updateStat('stat-risk', evt.risk_score + '/100');
      updateStat('stat-duration', (evt.duration_ms / 1000).toFixed(1) + 's');
      addLog('success', 'Scan complete — ' + evt.total_findings + ' findings, risk score ' + evt.risk_score);
      break;

    case 'LogMessage':
      addLog(evt.level, evt.message);
      break;
  }
}

function addFinding(evt) {
  const list = document.getElementById('findings-list');
  const sev = (evt.severity || 'medium').toLowerCase();
  const card = document.createElement('div');
  card.className = 'finding-card ' + sev;
  card.innerHTML = `
    <div class="finding-class">${evt.vuln_class}</div>
    <div class="finding-endpoint">${evt.node_id}</div>
    <span class="finding-severity ${sev}">${evt.severity}</span>
  `;
  card.onclick = () => showFindingDetail(evt);
  list.prepend(card);
  updateStat('stat-findings', list.children.length);
}

function addLog(level, msg) {
  const panel = document.getElementById('log-panel');
  const ts = new Date().toLocaleTimeString();
  const div = document.createElement('div');
  div.className = 'log-line ' + level;
  div.innerHTML = `<span class="timestamp">${ts}</span><span class="msg">${msg}</span>`;
  panel.appendChild(div);
  panel.scrollTop = panel.scrollHeight;
}

function updateStat(id, val) {
  document.getElementById(id).textContent = val;
}

// ========== MODAL ==========
function showNodeDetail(d) {
  document.getElementById('modal-title').textContent = d.label;
  document.getElementById('modal-body').innerHTML = `
    <p><strong>Type:</strong> ${d.node_type}</p>
    <p><strong>Status:</strong> ${d.status}</p>
    ${d.severity ? '<p><strong>Severity:</strong> '+d.severity+'</p>' : ''}
    ${d.confidence != null ? '<p><strong>Confidence:</strong> '+(d.confidence*100).toFixed(1)+'%</p>' : ''}
    <pre>${JSON.stringify(d.data, null, 2)}</pre>
  `;
  document.getElementById('modal-overlay').classList.add('active');
}

function showFindingDetail(f) {
  document.getElementById('modal-title').textContent = f.vuln_class;
  document.getElementById('modal-body').innerHTML = `
    <p><strong>Node:</strong> ${f.node_id}</p>
    <p><strong>Severity:</strong> ${f.severity}</p>
    <p><strong>Evidence:</strong></p>
    <pre>${f.evidence_preview || 'No evidence preview available'}</pre>
  `;
  document.getElementById('modal-overlay').classList.add('active');
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('active');
}

// ========== KEYBOARD ==========
document.addEventListener('keydown', (e) => {
  if (e.code === 'Space') {
    e.preventDefault();
    isPaused = !isPaused;
    fetch('/api/control', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({action: isPaused ? 'pause' : 'resume'})
    });
    addLog('info', isPaused ? 'Scan paused' : 'Scan resumed');
  }
  if (e.code === 'KeyR') {
    simulation.alpha(1).restart();
    addLog('info', 'Layout reset');
  }
  if (e.code === 'KeyF') {
    if (!document.fullscreenElement) document.documentElement.requestFullscreen();
    else document.exitFullscreen();
  }
  if (e.code === 'KeyE') exportSVG();
  if (e.code === 'Escape') closeModal();
});

function exportSVG() {
  const svgEl = document.getElementById('graph-svg');
  const data = new XMLSerializer().serializeToString(svgEl);
  const blob = new Blob([data], {type: 'image/svg+xml'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'aegis-graph.svg';
  a.click();
  addLog('info', 'Graph exported as SVG');
}

// ========== SSE CONNECTION ==========
function connectSSE() {
  const es = new EventSource('/api/graph');
  es.onmessage = (e) => {
    try {
      const evt = JSON.parse(e.data);
      handleEvent(evt);
    } catch(err) {
      console.error('Failed to parse SSE event:', err);
    }
  };
  es.onerror = () => {
    addLog('warn', 'SSE connection lost, reconnecting...');
    es.close();
    setTimeout(connectSSE, 2000);
  };
  addLog('info', 'Connected to AEGIS event stream');
}

connectSSE();
</script>
</body>
</html>
"##;

#[cfg(test)]
#[path = "dashboard_test.rs"]
mod dashboard_test;
