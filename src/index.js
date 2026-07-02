import { CONFIG, createConfig } from './config/index.js';
import { transformPath } from './config/platforms.js';

/**
 * Monitors performance metrics during request processing
 */
class PerformanceMonitor {
  /**
   * Initializes a new performance monitor
   */
  constructor() {
    this.startTime = Date.now();
    this.marks = new Map();
  }

  /**
   * Marks a timing point with the given name
   * @param {string} name - The name of the timing mark
   */
  mark(name) {
    if (this.marks.has(name)) {
      console.warn(`Mark with name ${name} already exists.`);
    }
    this.marks.set(name, Date.now() - this.startTime);
  }

  /**
   * Returns all collected metrics
   * @returns {Object.<string, number>} Object containing name-timestamp pairs
   */
  getMetrics() {
    return Object.fromEntries(this.marks.entries());
  }
}

/**
 * Detects if a request is a container registry operation
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is a container registry operation
 */
function isDockerRequest(request, url) {
  // Check for container registry API endpoints
  if (url.pathname.startsWith('/v2/')) {
    return true;
  }

  // Check for Docker-specific User-Agent
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.toLowerCase().includes('docker/')) {
    return true;
  }

  // Check for Docker-specific Accept headers
  const accept = request.headers.get('Accept') || '';
  if (
    accept.includes('application/vnd.docker.distribution.manifest') ||
    accept.includes('application/vnd.oci.image.manifest') ||
    accept.includes('application/vnd.docker.image.rootfs.diff.tar.gzip')
  ) {
    return true;
  }

  return false;
}

/**
 * Detects if a request is a Git operation
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is a Git operation
 */
function isGitRequest(request, url) {
  // Check for Git-specific endpoints
  if (url.pathname.endsWith('/info/refs')) {
    return true;
  }

  if (url.pathname.endsWith('/git-upload-pack') || url.pathname.endsWith('/git-receive-pack')) {
    return true;
  }

  // Check for Git user agents (more comprehensive check)
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.includes('git/') || userAgent.startsWith('git/')) {
    return true;
  }

  // Check for Git-specific query parameters
  if (url.searchParams.has('service')) {
    const service = url.searchParams.get('service');
    return service === 'git-upload-pack' || service === 'git-receive-pack';
  }

  // Check for Git-specific content types
  const contentType = request.headers.get('Content-Type') || '';
  if (contentType.includes('git-upload-pack') || contentType.includes('git-receive-pack')) {
    return true;
  }

  return false;
}

/**
 * Check if the request is for an AI inference provider
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is an AI inference request
 */
function isAIInferenceRequest(request, url) {
  // Check for AI inference provider paths (ip/{provider}/...)
  if (url.pathname.startsWith('/ip/')) {
    return true;
  }

  // Check for common AI inference API endpoints
  const aiEndpoints = [
    '/v1/chat/completions',
    '/v1/completions',
    '/v1/messages',
    '/v1/predictions',
    '/v1/generate',
    '/v1/embeddings',
    '/openai/v1/chat/completions'
  ];

  if (aiEndpoints.some(endpoint => url.pathname.includes(endpoint))) {
    return true;
  }

  // Check for AI-specific content types
  const contentType = request.headers.get('Content-Type') || '';
  if (contentType.includes('application/json') && request.method === 'POST') {
    // Additional check for common AI inference patterns in URL
    if (
      url.pathname.includes('/chat/') ||
      url.pathname.includes('/completions') ||
      url.pathname.includes('/generate') ||
      url.pathname.includes('/predict')
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Validates incoming requests against security rules
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @param {import('./config/index.js').ApplicationConfig} config - Configuration object
 * @returns {{valid: boolean, error?: string, status?: number}} Validation result
 */
function validateRequest(request, url, config = CONFIG) {
  // Allow POST method for Git, Docker, and AI inference operations
  const isGit = isGitRequest(request, url);
  const isDocker = isDockerRequest(request, url);
  const isAI = isAIInferenceRequest(request, url);

  const allowedMethods =
    isGit || isDocker || isAI
      ? ['GET', 'HEAD', 'POST', 'PUT', 'PATCH']
      : config.SECURITY.ALLOWED_METHODS;

  if (!allowedMethods.includes(request.method)) {
    return { valid: false, error: 'Method not allowed', status: 405 };
  }

  if (url.pathname.length > config.SECURITY.MAX_PATH_LENGTH) {
    return { valid: false, error: 'Path too long', status: 414 };
  }

  return { valid: true };
}

/**
 * Creates a standardized error response
 * @param {string} message - Error message
 * @param {number} status - HTTP status code
 * @param {boolean} includeDetails - Whether to include detailed error information
 * @returns {Response} Error response
 */
function createErrorResponse(message, status, includeDetails = false) {
  const errorBody = includeDetails
    ? JSON.stringify({ error: message, status, timestamp: new Date().toISOString() })
    : message;

  return new Response(errorBody, {
    status,
    headers: addSecurityHeaders(
      new Headers({
        'Content-Type': includeDetails ? 'application/json' : 'text/plain'
      })
    )
  });
}

/**
 * Adds security headers to the response
 * @param {Headers} headers - Headers object to modify
 * @returns {Headers} Modified headers object
 */
function addSecurityHeaders(headers) {
  headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('X-XSS-Protection', '1; mode=block');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Content-Security-Policy', "default-src 'none'; img-src 'self'; script-src 'none'");
  headers.set('Permissions-Policy', 'interest-cohort=()');
  return headers;
}

/**
 * Creates the homepage HTML for project deadline management
 * @returns {string}
 */
function getHomePageHtml() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Project DDL - 项目提醒系统</title>
  <style>
    body { background-color: white; margin: 0; }
    a { text-decoration: underline; text-decoration-color: currentColor; }
    .home {
      font-family: Roboto, Helvetica Neue, Helvetica, Arial, sans-serif;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
      max-width: 980px;
      margin-left: auto;
      margin-right: auto;
      padding: 18px 16px 28px;
      color: #2c3e50;
    }
    .title { font-size: 29px; color: #2c3e50; text-decoration: underline; text-decoration-color: currentColor; margin: 0; }
    .subtitle { color: #666; display: inline-block; margin-top: 6px; font-size: 14px; }
    .el-row { align-items: center; padding-top: 15px; font-size: 16px; }
    .zonedivider { margin-top: 8px; border-bottom: 1px solid #ebeef5; }
    .panel { margin-top: 12px; border: 1px solid #ebeef5; border-radius: 8px; padding: 12px; background: #fff; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .label { color: #666; font-size: 13px; margin-bottom: 4px; display: block; }
    .custom-search-input, input, textarea, select {
      width: 100%;
      border: 1px solid lightgray;
      border-radius: 4px;
      font-size: 14px;
      padding: 8px 10px;
      box-sizing: border-box;
      color: #2c3e50;
    }
    textarea { min-height: 76px; resize: vertical; }
    * input::placeholder, textarea::placeholder { color: lightgray; }
    .thaw-button--primary {
      background-color: #409eff;
      color: #fff;
      border: 1px solid #409eff;
      border-radius: 4px;
      padding: 7px 12px;
      font-size: 14px;
      cursor: pointer;
    }
    .btn-secondary {
      background-color: #fff;
      color: #409eff;
      border: 1px solid #b3d8ff;
      border-radius: 4px;
      padding: 7px 12px;
      font-size: 14px;
      cursor: pointer;
    }
    .btn-danger {
      background: #fff;
      color: #f56c6c;
      border: 1px solid #fbc4c4;
      border-radius: 4px;
      padding: 7px 12px;
      font-size: 14px;
      cursor: pointer;
    }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .conf-title { font-size: 20px; font-weight: 400; color: black; }
    .countdown-display { font-size: 20px; font-weight: 400; color: black; }
    .countdown-value { display: inline-flex; align-items: center; }
    .thaw-table-cell-layout { display: block; padding: 12px 0; border-bottom: 1px solid #ebeef5; }
    .thaw-table-cell-layout:last-child { border-bottom: none; }
    .meta { color: #666; font-size: 13px; }
    .tag-container { margin-top: 6px; display: flex; gap: 6px; flex-wrap: wrap; }
    .plain-tag {
      background-color: #fff;
      border-color: #b3d8ff;
      border-radius: 4px;
      border-width: 1px;
      border-style: solid;
      height: 20px;
      line-height: 18px;
      padding: 0 5px;
      font-size: 12px;
      color: #409eff;
    }
    .editor {
      margin-top: 10px;
      border: 1px dashed #b3d8ff;
      border-radius: 8px;
      padding: 10px;
      background: #f8fbff;
    }
    .reminder-item {
      border: 1px solid #ebeef5;
      border-left: 4px solid #409eff;
      padding: 8px;
      border-radius: 4px;
      margin-bottom: 8px;
      font-size: 14px;
      color: #555;
    }
    .reminder-item.warn { border-left-color: #e6a23c; background: #fdf6ec; }
    .reminder-item.danger { border-left-color: #f56c6c; background: #fef0f0; }
    .footer {
      height: 20px;
      padding-top: 8px;
      color: #666;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 10px;
      font-size: 13px;
    }
    @media (max-width: 768px) {
      .grid-2 { grid-template-columns: 1fr; }
      .footer { flex-direction: column; height: auto; gap: 4px; }
    }
  </style>
</head>
<body>
  <div class="home">
    <h1 class="title">Project DDL</h1>
    <span class="subtitle">沿用 CCF DDL 风格（配色/字号/卡片结构），并支持在前端直接编辑项目（模拟后端管理）。</span>

    <div class="el-row zonedivider"></div>

    <section class="panel">
      <div class="grid-2">
        <div>
          <label class="label">项目名称</label>
          <input id="name" class="custom-search-input" placeholder="例如：毕业设计" />
        </div>
        <div>
          <label class="label">提醒天数（逗号分隔）</label>
          <input id="reminderDays" value="14,7,3,1" class="custom-search-input" />
        </div>
      </div>
      <div class="grid-2" style="margin-top:10px">
        <div>
          <label class="label">开始日期</label>
          <input id="startDate" type="date" />
        </div>
        <div>
          <label class="label">截止日期</label>
          <input id="endDate" type="date" />
        </div>
      </div>
      <div style="margin-top:10px">
        <label class="label">里程碑（每行：标题|YYYY-MM-DD）</label>
        <textarea id="milestones" placeholder="开题|2026-01-10
中期检查|2026-02-10"></textarea>
      </div>
      <div class="actions" style="margin-top:10px">
        <button id="addBtn" class="thaw-button--primary">添加项目</button>
        <button id="notifyBtn" class="btn-secondary">开启浏览器提醒</button>
        <input type="file" id="importFile" accept="application/json" style="max-width:300px" />
      </div>
    </section>

    <section class="grid-2" style="margin-top:12px; align-items:start">
      <article class="panel">
        <div class="conf-title">项目时间轴（前端）</div>
        <div id="projectList"></div>
      </article>
      <article class="panel">
        <div class="conf-title">项目编辑（后端管理台）</div>
        <p class="meta">点击左侧项目的“编辑”，不跳转，在本页完成调整。</p>
        <div class="grid-2">
          <div>
            <label class="label">选择项目</label>
            <select id="editSelect"></select>
          </div>
          <div style="display:flex;align-items:end">
            <button id="loadEdit" class="btn-secondary" style="width:100%">加载编辑器</button>
          </div>
        </div>
        <div id="editArea" class="editor" style="display:none"></div>

        <div style="margin-top:14px" class="conf-title">提醒列表</div>
        <div id="reminderList" style="margin-top:8px"></div>
      </article>
    </section>

    <div class="footer">
      <span>Data source: Manual / JSON import</span>
      <span>Inspired by CCF DDL style</span>
    </div>
  </div>

  <script>
    const key = 'project-ddl-items-v3';
    let projects = JSON.parse(localStorage.getItem(key) || '[]');

    const $ = id => document.getElementById(id);
    const days = (a, b) => Math.ceil((new Date(b) - new Date(a)) / 86400000);
    const clamp = (n, l, h) => Math.max(l, Math.min(h, n));

    function parseMilestones(text) {
      return text
        .split('\n')
        .map(v => v.trim())
        .filter(Boolean)
        .map(line => {
          const [title, date] = line.split('|').map(v => v && v.trim());
          return { title, date };
        })
        .filter(v => v.title && v.date);
    }

    function serializeMilestones(arr) {
      return (arr || []).map(v => v.title + '|' + v.date).join('\n');
    }

    function save() {
      localStorage.setItem(key, JSON.stringify(projects));
    }

    function collectReminders() {
      const now = new Date();
      const out = [];
      projects.forEach(p => {
        const d = days(now, p.endDate);
        (p.reminderDays || [14, 7, 3, 1]).forEach(n => {
          if (d === n)
            out.push({
              level: n <= 1 ? 'danger' : 'warn',
              text: '项目「' + p.name + '」距截止还有 ' + n + ' 天'
            });
        });
        (p.milestones || []).forEach(m => {
          const md = days(now, m.date);
          if (md >= 0 && md <= 3)
            out.push({
              level: md <= 1 ? 'danger' : 'warn',
              text: '里程碑「' + m.title + '」还有 ' + md + ' 天'
            });
        });
      });
      return out;
    }

    function notify(list) {
      if (!('Notification' in window) || Notification.permission !== 'granted') return;
      list.slice(0, 2).forEach(item => new Notification('Project DDL 提醒', { body: item.text }));
    }

    function renderEditSelector() {
      const sel = $('editSelect');
      if (!projects.length) {
        sel.innerHTML = '<option value="">暂无项目</option>';
        return;
      }
      sel.innerHTML = projects
        .map((p, i) => '<option value="' + i + '">' + p.name + '</option>')
        .join('');
    }

    function renderEditArea(index) {
      const box = $('editArea');
      if (index === '' || projects[index] == null) {
        box.style.display = 'none';
        return;
      }
      const p = projects[index];
      box.style.display = 'block';
      box.innerHTML =
        '<div class="grid-2"><div><label class="label">项目名称</label><input id="eName" value="' +
        (p.name || '') +
        '" /></div>' +
        '<div><label class="label">提醒天数</label><input id="eReminder" value="' +
        (p.reminderDays || []).join(',') +
        '" /></div></div>' +
        '<div class="grid-2" style="margin-top:10px"><div><label class="label">开始日期</label><input id="eStart" type="date" value="' +
        (p.startDate || '') +
        '" /></div>' +
        '<div><label class="label">截止日期</label><input id="eEnd" type="date" value="' +
        (p.endDate || '') +
        '" /></div></div>' +
        '<label class="label" style="margin-top:10px">里程碑</label><textarea id="eMilestones">' +
        serializeMilestones(p.milestones || []) +
        '</textarea>' +
        '<div class="actions" style="margin-top:10px"><button id="saveEdit" class="thaw-button--primary">保存修改</button><button id="deleteEdit" class="btn-danger">删除项目</button></div>';

      $('saveEdit').onclick = () => {
        projects[index] = {
          ...projects[index],
          name: $('eName').value.trim(),
          startDate: $('eStart').value,
          endDate: $('eEnd').value,
          milestones: parseMilestones($('eMilestones').value),
          reminderDays: $('eReminder')
            .value.split(',')
            .map(v => Number(v.trim()))
            .filter(Boolean)
        };
        render();
      };

      $('deleteEdit').onclick = () => {
        if (!confirm('确认删除该项目？')) return;
        projects.splice(index, 1);
        box.style.display = 'none';
        render();
      };
    }

    function render() {
      const now = new Date();
      projects.sort((a, b) => new Date(a.endDate) - new Date(b.endDate));
      const list = $('projectList');

      if (!projects.length) {
        list.innerHTML = '<p class="meta" style="padding:8px 0">还没有项目，先新增或导入一个。</p>';
      } else {
        list.innerHTML = projects
          .map((p, i) => {
            const total = Math.max(days(p.startDate, p.endDate), 1);
            const passed = clamp(days(p.startDate, now), 0, total);
            const percent = Math.round((passed / total) * 100);
            const left = Math.max(days(now, p.endDate), 0);
            const ms = (p.milestones || [])
              .map(m => '<span class="plain-tag">' + m.title + ' · ' + m.date + '</span>')
              .join('');
            return (
              '<div class="thaw-table-cell-layout">' +
              '<div style="display:flex;justify-content:space-between;gap:8px;align-items:center">' +
              '<div class="conf-title" style="font-size:18px">' +
              p.name +
              '</div>' +
              '<div class="countdown-display"><span class="countdown-value">D-' +
              left +
              '</span> <button class="btn-secondary" style="padding:4px 8px" data-edit="' +
              i +
              '">编辑</button></div>' +
              '</div>' +
              '<div class="meta" style="margin-top:6px">' +
              p.startDate +
              ' → ' +
              p.endDate +
              ' · 进度 ' +
              percent +
              '%</div>' +
              '<div style="height:8px;border-radius:6px;background:#ebeef5;margin-top:8px;overflow:hidden"><div style="width:' +
              percent +
              '%;height:8px;background:#409eff"></div></div>' +
              '<div class="tag-container">' +
              ms +
              '</div>' +
              '</div>'
            );
          })
          .join('');
      }

      list.querySelectorAll('[data-edit]').forEach(btn => {
        btn.onclick = () => {
          $('editSelect').value = btn.getAttribute('data-edit');
          renderEditArea($('editSelect').value);
          window.scrollTo({ top: 380, behavior: 'smooth' });
        };
      });

      const reminders = collectReminders();
      $('reminderList').innerHTML = reminders.length
        ? reminders
            .map(v => '<div class="reminder-item ' + v.level + '">' + v.text + '</div>')
            .join('')
        : '<p class="meta">暂无近期提醒。</p>';

      renderEditSelector();
      notify(reminders);
      save();
    }

    $('addBtn').onclick = () => {
      const name = $('name').value.trim();
      const startDate = $('startDate').value;
      const endDate = $('endDate').value;
      if (!name || !startDate || !endDate) return alert('请填写完整信息');
      projects.push({
        name,
        startDate,
        endDate,
        milestones: parseMilestones($('milestones').value),
        reminderDays: $('reminderDays')
          .value.split(',')
          .map(v => Number(v.trim()))
          .filter(Boolean)
      });
      render();
    };

    $('loadEdit').onclick = () => renderEditArea($('editSelect').value);

    $('importFile').onchange = async e => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      try {
        const arr = JSON.parse(await file.text());
        if (!Array.isArray(arr)) throw new Error('JSON 必须是数组');
        projects = projects.concat(arr);
        render();
      } catch (err) {
        alert('导入失败: ' + err.message);
      }
    };

    $('notifyBtn').onclick = async () => {
      if (!('Notification' in window)) return alert('浏览器不支持通知');
      const p = await Notification.requestPermission();
      alert(p === 'granted' ? '提醒已开启' : '未授予通知权限');
    };

    render();
    setInterval(render, 60000);
  </script>
</body>
</html>`;
}

/**
 * Creates homepage response with permissive CSP for inline app resources
 * @returns {Response}
 */
function createHomePageResponse() {
  const headers = new Headers({ 'Content-Type': 'text/html; charset=UTF-8' });
  addSecurityHeaders(headers);
  headers.set(
    'Content-Security-Policy',
    "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
  );
  return new Response(getHomePageHtml(), { status: 200, headers });
}

/**
 * Parses Docker WWW-Authenticate header
 * @param {string} authenticateStr - The WWW-Authenticate header value
 * @returns {{realm: string, service: string}} Parsed authentication info
 */
function parseAuthenticate(authenticateStr) {
  // sample: Bearer realm="https://auth.ipv6.docker.com/token",service="registry.docker.io"
  const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
  const matches = authenticateStr.match(re);
  if (matches == null || matches.length < 2) {
    throw new Error(`invalid Www-Authenticate Header: ${authenticateStr}`);
  }
  return {
    realm: matches[0],
    service: matches[1]
  };
}

/**
 * Fetches authentication token from container registry
 * @param {{realm: string, service: string}} wwwAuthenticate - Authentication info
 * @param {string} scope - The scope for the token
 * @param {string} authorization - Authorization header value
 * @returns {Promise<Response>} Token response
 */
async function fetchToken(wwwAuthenticate, scope, authorization) {
  const url = new URL(wwwAuthenticate.realm);
  if (wwwAuthenticate.service.length) {
    url.searchParams.set('service', wwwAuthenticate.service);
  }
  if (scope) {
    url.searchParams.set('scope', scope);
  }
  const headers = new Headers();
  if (authorization) {
    headers.set('Authorization', authorization);
  }
  return await fetch(url, { method: 'GET', headers });
}

/**
 * Creates unauthorized response for container registry
 * @param {URL} url - Request URL
 * @returns {Response} Unauthorized response
 */
function responseUnauthorized(url) {
  const headers = new Headers();
  headers.set('WWW-Authenticate', `Bearer realm="https://${url.hostname}/v2/auth",service="Xget"`);
  return new Response(JSON.stringify({ message: 'UNAUTHORIZED' }), {
    status: 401,
    headers
  });
}

/**
 * Handles incoming requests with caching, retries, and security measures
 * @param {Request} request - The incoming request
 * @param {Object} env - Environment variables
 * @param {ExecutionContext} ctx - Cloudflare Workers execution context
 * @returns {Promise<Response>} The response object
 */
async function handleRequest(request, env, ctx) {
  try {
    // Create config with environment variable overrides
    const config = env ? createConfig(env) : CONFIG;
    const url = new URL(request.url);
    const isDocker = isDockerRequest(request, url);

    const monitor = new PerformanceMonitor();

    // Handle Docker API version check
    if (isDocker && (url.pathname === '/v2/' || url.pathname === '/v2')) {
      const headers = new Headers({
        'Docker-Distribution-Api-Version': 'registry/2.0',
        'Content-Type': 'application/json'
      });
      addSecurityHeaders(headers);
      return new Response('{}', { status: 200, headers });
    }

    // Serve homepage
    if (url.pathname === '/' || url.pathname === '') {
      return createHomePageResponse();
    }

    const validation = validateRequest(request, url, config);
    if (!validation.valid) {
      return createErrorResponse(validation.error || 'Validation failed', validation.status || 400);
    }

    // Parse platform and path
    let platform;
    let effectivePath = url.pathname;

    // Handle container registry paths specially
    if (isDocker) {
      // For Docker requests (excluding version check which is handled above),
      // check if they have /cr/ prefix
      if (!url.pathname.startsWith('/cr/') && !url.pathname.startsWith('/v2/cr/')) {
        return createErrorResponse('container registry requests must use /cr/ prefix', 400);
      }
      // Remove /v2 from the path for container registry API consistency if present
      effectivePath = url.pathname.replace(/^\/v2/, '');
    }

    // Platform detection using transform patterns
    // Sort platforms by path length (descending) to prioritize more specific paths
    // e.g., conda/community should match before conda, pypi/files before pypi
    const sortedPlatforms = Object.keys(config.PLATFORMS).sort((a, b) => {
      const pathA = `/${a.replace('-', '/')}/`;
      const pathB = `/${b.replace('-', '/')}/`;
      return pathB.length - pathA.length;
    });

    platform =
      sortedPlatforms.find(key => {
        const expectedPrefix = `/${key.replace('-', '/')}/`;
        return effectivePath.startsWith(expectedPrefix);
      }) || effectivePath.split('/')[1];

    if (!platform || !config.PLATFORMS[platform]) {
      return createErrorResponse('invalid platform', 400);
    }

    // Transform URL based on platform using unified logic
    const targetPath = transformPath(effectivePath, platform);

    // For container registries, ensure we add the /v2 prefix for the Docker API
    let finalTargetPath;
    if (platform.startsWith('cr-')) {
      finalTargetPath = `/v2${targetPath}`;
    } else {
      finalTargetPath = targetPath;
    }

    const targetUrl = `${config.PLATFORMS[platform]}${finalTargetPath}${url.search}`;
    const authorization = request.headers.get('Authorization');

    // Handle Docker authentication
    if (isDocker && url.pathname === '/v2/auth') {
      const newUrl = new URL(`${config.PLATFORMS[platform]}/v2/`);
      const resp = await fetch(newUrl.toString(), {
        method: 'GET',
        redirect: 'follow'
      });
      if (resp.status !== 401) {
        return resp;
      }
      const authenticateStr = resp.headers.get('WWW-Authenticate');
      if (authenticateStr === null) {
        return resp;
      }
      const wwwAuthenticate = parseAuthenticate(authenticateStr);
      const scope = url.searchParams.get('scope');
      return await fetchToken(wwwAuthenticate, scope || '', authorization || '');
    }

    // Check if this is a Git operation
    const isGit = isGitRequest(request, url);

    // Check if this is an AI inference request
    const isAI = isAIInferenceRequest(request, url);

    // Check cache first (skip cache for Git, Docker, and AI inference operations)
    /** @type {Cache} */
    // @ts-ignore - Cloudflare Workers cache API
    const cache = caches.default;
    let response;

    if (!isGit && !isDocker && !isAI) {
      // For Range requests, try cache match first
      const cacheKey = new Request(targetUrl, request);
      response = await cache.match(cacheKey);
      if (response) {
        monitor.mark('cache_hit');
        return response;
      }

      // If Range request missed cache, try with original request to see if we have full content cached
      const rangeHeader = request.headers.get('Range');
      if (rangeHeader) {
        const fullContentKey = new Request(targetUrl, {
          method: request.method,
          headers: new Headers(
            [...request.headers.entries()].filter(([k]) => k.toLowerCase() !== 'range')
          )
        });
        response = await cache.match(fullContentKey);
        if (response) {
          monitor.mark('cache_hit_full_content');
          return response;
        }
      }
    }

    /** @type {RequestInit} */
    const fetchOptions = {
      method: request.method,
      headers: new Headers(),
      redirect: 'follow'
    };

    // Add body for POST/PUT/PATCH requests (Git/Docker/AI inference operations)
    if (['POST', 'PUT', 'PATCH'].includes(request.method) && (isGit || isDocker || isAI)) {
      fetchOptions.body = request.body;
    }

    // Cast headers to Headers for proper typing
    const requestHeaders = /** @type {Headers} */ (fetchOptions.headers);

    // Set appropriate headers for Git/Docker/AI vs regular requests
    if (isGit || isDocker || isAI) {
      // For Git/Docker/AI operations, copy all headers from the original request
      // This ensures protocol compliance
      for (const [key, value] of request.headers.entries()) {
        // Skip headers that might cause issues with proxying
        if (!['host', 'connection', 'upgrade', 'proxy-connection'].includes(key.toLowerCase())) {
          requestHeaders.set(key, value);
        }
      }

      // Set Git-specific headers if not present
      if (isGit && !requestHeaders.has('User-Agent')) {
        requestHeaders.set('User-Agent', 'git/2.34.1');
      }

      // For Git upload-pack requests, ensure proper content type
      if (isGit && request.method === 'POST' && url.pathname.endsWith('/git-upload-pack')) {
        if (!requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/x-git-upload-pack-request');
        }
      }

      // For Git receive-pack requests, ensure proper content type
      if (isGit && request.method === 'POST' && url.pathname.endsWith('/git-receive-pack')) {
        if (!requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/x-git-receive-pack-request');
        }
      }

      // For AI inference requests, ensure proper content type and headers
      if (isAI) {
        // Ensure JSON content type for AI API requests if not already set
        if (request.method === 'POST' && !requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/json');
        }

        // Set appropriate User-Agent for AI requests if not present
        if (!requestHeaders.has('User-Agent')) {
          requestHeaders.set('User-Agent', 'Xget-AI-Proxy/1.0');
        }
      }
    } else {
      // Regular file download headers
      Object.assign(fetchOptions, {
        cf: {
          http3: true,
          cacheTtl: config.CACHE_DURATION,
          cacheEverything: true,
          minify: {
            javascript: true,
            css: true,
            html: true
          },
          preconnect: true
        }
      });

      requestHeaders.set('Accept-Encoding', 'gzip, deflate, br');
      requestHeaders.set('Connection', 'keep-alive');
      requestHeaders.set('User-Agent', 'Wget/1.21.3');
      requestHeaders.set('Origin', request.headers.get('Origin') || '*');

      // Handle range requests - but don't forward Range header if we need to cache full content
      const rangeHeader = request.headers.get('Range');

      // Detect media files to avoid compression for better Range support
      const isMediaFile = targetUrl.match(
        /\.(mp4|avi|mkv|mov|wmv|flv|webm|mp3|wav|flac|aac|ogg|jpg|jpeg|png|gif|bmp|svg|pdf|zip|rar|7z|tar|gz|bz2|xz)$/i
      );

      if (isMediaFile || rangeHeader) {
        // For media files or range requests, avoid compression to ensure proper byte-range support
        requestHeaders.set('Accept-Encoding', 'identity');
      }

      // For Range requests, we need to decide whether to forward the Range header
      // If we want to cache the full content first, don't send Range to origin
      if (rangeHeader) {
        // Check if we already have full content cached
        const fullContentKey = new Request(targetUrl, {
          method: request.method,
          headers: new Headers(
            [...request.headers.entries()].filter(([k]) => k.toLowerCase() !== 'range')
          )
        });

        // If we're going to try to get full content for caching, don't send Range header
        // This will be handled in the retry logic
        requestHeaders.set('Range', rangeHeader);
      }
    }

    // Implement retry mechanism
    let attempts = 0;
    while (attempts < config.MAX_RETRIES) {
      try {
        monitor.mark(`attempt_${attempts}`);

        // Fetch with timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.TIMEOUT_SECONDS * 1000);

        // For Git/Docker operations, don't use Cloudflare-specific options
        const finalFetchOptions =
          isGit || isDocker
            ? { ...fetchOptions, signal: controller.signal }
            : { ...fetchOptions, signal: controller.signal };

        // Special handling for HEAD requests to ensure Content-Length header
        if (request.method === 'HEAD') {
          // First, try the HEAD request
          response = await fetch(targetUrl, finalFetchOptions);

          // If HEAD request succeeds but lacks Content-Length, do a GET request to get it
          if (response.ok && !response.headers.get('Content-Length')) {
            const getResponse = await fetch(targetUrl, {
              ...finalFetchOptions,
              method: 'GET'
            });

            if (getResponse.ok) {
              // Create a new response with HEAD method but include Content-Length from GET
              const headHeaders = new Headers(response.headers);
              const contentLength = getResponse.headers.get('Content-Length');

              if (contentLength) {
                headHeaders.set('Content-Length', contentLength);
              } else {
                // If still no Content-Length, calculate it from the response body
                const arrayBuffer = await getResponse.arrayBuffer();
                headHeaders.set('Content-Length', arrayBuffer.byteLength.toString());
              }

              response = new Response(null, {
                status: getResponse.status,
                statusText: getResponse.statusText,
                headers: headHeaders
              });
            }
          }
        } else {
          response = await fetch(targetUrl, finalFetchOptions);
        }

        clearTimeout(timeoutId);

        if (response.ok || response.status === 206) {
          monitor.mark('success');
          break;
        }

        // For container registry, handle authentication challenges more intelligently
        if (isDocker && response.status === 401) {
          monitor.mark('docker_auth_challenge');

          // For container registries, first check if we can get a token without credentials
          // This allows access to public repositories
          const authenticateStr = response.headers.get('WWW-Authenticate');
          if (authenticateStr) {
            try {
              const wwwAuthenticate = parseAuthenticate(authenticateStr);

              // Infer scope from the request path for container registry requests
              let scope = '';
              const pathParts = url.pathname.split('/');
              if (pathParts.length >= 4 && pathParts[1] === 'v2') {
                // Extract repository name from path like /v2/cr/ghcr/nginxinc/nginx-unprivileged/manifests/latest
                // Remove /v2 and platform prefix to get the repo path
                const repoPath = pathParts.slice(4).join('/'); // Skip /v2/cr/[registry]
                const repoParts = repoPath.split('/');
                if (repoParts.length >= 1) {
                  const repoName = repoParts.slice(0, -2).join('/'); // Remove /manifests/tag or /blobs/sha
                  if (repoName) {
                    scope = `repository:${repoName}:pull`;
                  }
                }
              }

              // Try to get a token for public access (without authorization)
              const tokenResponse = await fetchToken(wwwAuthenticate, scope || '', '');
              if (tokenResponse.ok) {
                const tokenData = await tokenResponse.json();
                if (tokenData.token) {
                  // Retry the original request with the obtained token
                  const retryHeaders = new Headers(requestHeaders);
                  retryHeaders.set('Authorization', `Bearer ${tokenData.token}`);

                  const retryResponse = await fetch(targetUrl, {
                    ...finalFetchOptions,
                    headers: retryHeaders
                  });

                  if (retryResponse.ok) {
                    response = retryResponse;
                    monitor.mark('success');
                    break;
                  }
                }
              }
            } catch (error) {
              console.log('Token fetch failed:', error);
            }
          }

          // If token fetch failed or didn't work, return the unauthorized response
          // Only return this if we truly can't access the resource
          return responseUnauthorized(url);
        }

        // Don't retry on client errors (4xx) - these won't improve with retries
        if (response.status >= 400 && response.status < 500) {
          monitor.mark('client_error');
          break;
        }

        attempts++;
        if (attempts < config.MAX_RETRIES) {
          await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * attempts));
        }
      } catch (error) {
        attempts++;
        if (error instanceof Error && error.name === 'AbortError') {
          return createErrorResponse('Request timeout', 408);
        }
        if (attempts >= config.MAX_RETRIES) {
          const message = error instanceof Error ? error.message : String(error);
          return createErrorResponse(
            `Failed after ${config.MAX_RETRIES} attempts: ${message}`,
            500,
            true
          );
        }
        // Wait before retrying
        await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * attempts));
      }
    }

    // Check if we have a valid response after all attempts
    if (!response) {
      return createErrorResponse('No response received after all retry attempts', 500, true);
    }

    // If response is still not ok after all retries, return the error
    if (!response.ok && response.status !== 206) {
      // For Docker authentication errors that we couldn't resolve with anonymous tokens,
      // return a more helpful error message
      if (isDocker && response.status === 401) {
        const errorText = await response.text().catch(() => '');
        return createErrorResponse(
          `Authentication required for this container registry resource. This may be a private repository. Original error: ${errorText}`,
          401,
          true
        );
      }
      const errorText = await response.text().catch(() => 'Unknown error');
      return createErrorResponse(
        `Upstream server error (${response.status}): ${errorText}`,
        response.status,
        true
      );
    }

    // Handle URL rewriting for different platforms
    let responseBody = response.body;

    // Handle PyPI simple index URL rewriting
    if (platform === 'pypi' && response.headers.get('content-type')?.includes('text/html')) {
      const originalText = await response.text();
      // Rewrite URLs in the response body to go through the Cloudflare Worker
      // files.pythonhosted.org URLs should be rewritten to go through our pypi/files endpoint
      const rewrittenText = originalText.replace(
        /https:\/\/files\.pythonhosted\.org/g,
        `${url.origin}/pypi/files`
      );
      responseBody = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(rewrittenText));
          controller.close();
        }
      });
    }

    // Handle npm registry URL rewriting
    if (platform === 'npm' && response.headers.get('content-type')?.includes('application/json')) {
      const originalText = await response.text();
      // Rewrite tarball URLs in npm registry responses to go through our npm endpoint
      // https://registry.npmjs.org/package/-/package-version.tgz -> https://xget.xi-xu.me/npm/package/-/package-version.tgz
      const rewrittenText = originalText.replace(
        /https:\/\/registry\.npmjs\.org\/([^\/]+)/g,
        `${url.origin}/npm/$1`
      );
      responseBody = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(rewrittenText));
          controller.close();
        }
      });
    }

    // Prepare response headers
    const headers = new Headers(response.headers);

    if (isGit || isDocker) {
      // For Git/Docker operations, preserve all headers from the upstream response
      // These protocols are very sensitive to header changes
      // Don't add any additional headers that might interfere with protocol operation
      // The response headers from upstream should be passed through as-is
    } else {
      // Regular file download headers
      headers.set('Cache-Control', `public, max-age=${config.CACHE_DURATION}`);
      headers.set('X-Content-Type-Options', 'nosniff');
      headers.set('Accept-Ranges', 'bytes');

      // Ensure Content-Length is present for proper Range support
      if (!headers.has('Content-Length') && response.status === 200) {
        // If Content-Length is missing and we have access to the body, calculate it
        try {
          const contentLength = response.headers.get('Content-Length');
          if (contentLength) {
            headers.set('Content-Length', contentLength);
          }
        } catch (error) {
          console.warn('Could not set Content-Length header:', error);
        }
      }

      addSecurityHeaders(headers);
    }

    // Create final response
    const finalResponse = new Response(responseBody, {
      status: response.status,
      headers
    });

    // Cache successful responses (skip caching for Git, Docker, and AI inference operations)
    // Only cache GET and HEAD requests to avoid "Cannot cache response to non-GET request" errors
    // IMPORTANT: Only cache 200 responses, NOT 206 responses (Cloudflare Workers Cache API rejects 206)
    if (
      !isGit &&
      !isDocker &&
      !isAI &&
      ['GET', 'HEAD'].includes(request.method) &&
      response.ok &&
      response.status === 200 // Only cache complete responses (200), not partial content (206)
    ) {
      // For Range requests that resulted in 200, cache the full response
      const rangeHeader = request.headers.get('Range');
      const cacheKey = rangeHeader
        ? new Request(targetUrl, {
            method: request.method,
            headers: new Headers(
              [...request.headers.entries()].filter(([k]) => k.toLowerCase() !== 'range')
            )
          })
        : new Request(targetUrl, request);

      ctx.waitUntil(cache.put(cacheKey, finalResponse.clone()));

      // If this was originally a Range request and we got a 200 (full content),
      // try cache.match again with the original Range request to get 206 response
      if (rangeHeader && response.status === 200) {
        const rangedResponse = await cache.match(new Request(targetUrl, request));
        if (rangedResponse) {
          monitor.mark('range_cache_hit_after_full_cache');
          return rangedResponse;
        }
      }
    }

    monitor.mark('complete');
    return isGit || isDocker || isAI
      ? finalResponse
      : addPerformanceHeaders(finalResponse, monitor);
  } catch (error) {
    console.error('Error handling request:', error);
    const message = error instanceof Error ? error.message : String(error);
    return createErrorResponse(`Internal Server Error: ${message}`, 500, true);
  }
}

/**
 * Adds performance metrics to response headers
 * @param {Response} response - The response object
 * @param {PerformanceMonitor} monitor - Performance monitor instance
 * @returns {Response} New response with performance headers
 */
function addPerformanceHeaders(response, monitor) {
  const headers = new Headers(response.headers);
  headers.set('X-Performance-Metrics', JSON.stringify(monitor.getMetrics()));
  addSecurityHeaders(headers);
  return new Response(response.body, {
    status: response.status,
    headers
  });
}

export default {
  /**
   * Main entry point for the Cloudflare Worker
   * @param {Request} request - The incoming request
   * @param {Object} env - Environment variables
   * @param {ExecutionContext} ctx - Cloudflare Workers execution context
   * @returns {Promise<Response>} The response object
   */
  fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  }
};
