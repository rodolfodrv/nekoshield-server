const express = require('express');
const cors = require('cors');
const https = require('https');
const http = require('http');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: false }));

const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_SECRET = process.env.PAYPAL_SECRET;

// ─── SUPABASE HELPERS ───────────────────────────────────────────────────────

function supabaseRequest(method, path, body) {
  return new Promise(function(resolve) {
    if (!SUPABASE_URL || !SUPABASE_KEY) { resolve(null); return; }
    var url = new URL(SUPABASE_URL);
    var bodyStr = body ? JSON.stringify(body) : null;
    var options = {
      hostname: url.hostname,
      path: '/rest/v1/' + path,
      method: method,
      headers: {
        'apikey': SUPABASE_KEY,
        'Authorization': 'Bearer ' + SUPABASE_KEY,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation'
      }
    };
    if (bodyStr) options.headers['Content-Length'] = Buffer.byteLength(bodyStr);
    var req = https.request(options, function(response) {
      var data = '';
      response.on('data', function(chunk) { data += chunk; });
      response.on('end', function() {
        try { resolve(JSON.parse(data)); }
        catch(e) { resolve(null); }
      });
    });
    req.on('error', function() { resolve(null); });
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

async function getUserTokens(email) {
  var result = await supabaseRequest('GET', 'user_tokens?email=eq.' + encodeURIComponent(email) + '&select=*');
  if (result && result.length > 0) return result[0];
  return null;
}

async function createUser(email) {
  var result = await supabaseRequest('POST', 'user_tokens', { email: email, tokens: 50, total_checks: 0 });
  if (result && result.length > 0) return result[0];
  return null;
}

async function deductToken(email) {
  var user = await getUserTokens(email);
  if (!user || user.tokens <= 0) return false;
  await supabaseRequest('PATCH', 'user_tokens?email=eq.' + encodeURIComponent(email), {
    tokens: user.tokens - 5,
    total_checks: user.total_checks + 1
  });
  return true;
}

// FIXED: now saves URL so the cache actually works
async function saveAnalysis(email, ip, type, result, score, brand, url) {
  await supabaseRequest('POST', 'analysis_history', {
    email: email || null,
    ip_address: ip,
    type: type,
    result: result,
    score: score,
    brand: brand || null,
    url: url || null
  });
}

async function checkOwnDatabase(url) {
  var result = await supabaseRequest('GET', 'analysis_history?url=eq.' + encodeURIComponent(url) + '&order=created_at.desc&limit=1&select=*');
  if (result && result.length > 0) {
    var record = result[0];
    if (record.result === 'dangerous' || record.result === 'suspicious') {
      return {
        signals: [{ type: 'danger', label: 'NekoShield Database', value: 'Previously flagged as ' + record.result }],
        score: record.result === 'dangerous' ? 80 : 40,
        fromCache: true
      };
    }
  }
  return null;
}

// ─── HEALTH CHECK ───────────────────────────────────────────────────────────

app.get('/', function(req, res) {
  res.json({
    status: 'NekoShield API running',
    hasGoogle: !!GOOGLE_API_KEY,
    hasAnthropic: !!ANTHROPIC_API_KEY,
    hasSupabase: !!SUPABASE_URL,
  });
});

// ─── REGISTER / LOGIN ───────────────────────────────────────────────────────

app.post('/register', async function(req, res) {
  var email = req.body.email;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });

  var existing = await getUserTokens(email);
  if (existing) {
    return res.json({ success: true, tokens: existing.tokens, message: 'Welcome back!' });
  }

  var newUser = await createUser(email);
  if (newUser) {
    res.json({ success: true, tokens: 50, message: 'Account created! You have 50 free NekoTokens.' });
  } else {
    res.status(500).json({ error: 'Could not create account' });
  }
});

app.post('/tokens', async function(req, res) {
  var email = req.body.email;
  if (!email) return res.status(400).json({ error: 'Email required' });
  var user = await getUserTokens(email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ tokens: user.tokens, total_checks: user.total_checks });
});

// ─── URL PATTERN ANALYSIS (no external API) ─────────────────────────────────

function analyzeUrlPattern(url) {
  var signals = [];
  var score = 0;

  try {
    var parsed = new URL(url);
    var hostname = parsed.hostname.toLowerCase();
    var fullUrl = url.toLowerCase();
    var parts = hostname.split('.');
    var registeredDomain = parts.slice(-2).join('.');

    // 1. IP address in URL instead of domain
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      signals.push({ type: 'danger', label: 'URL Analysis', value: 'IP address used instead of domain name' });
      score += 40;
    }

    // 2. @ symbol in URL (tricks browser into ignoring left part)
    if (url.includes('@')) {
      signals.push({ type: 'danger', label: 'URL Analysis', value: 'Contains @ symbol — common phishing trick' });
      score += 35;
    }

    // 3. Punycode / IDN homograph attack
    if (hostname.includes('xn--')) {
      signals.push({ type: 'warning', label: 'URL Analysis', value: 'Contains international characters that may mimic real domains' });
      score += 25;
    }

    // 4. Suspicious TLD (free or commonly abused)
    var suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
      '.click', '.loan', '.work', '.date', '.racing', '.download',
      '.accountant', '.stream', '.online', '.site', '.tech'];
    var hasSuspiciousTld = suspiciousTlds.some(function(tld) { return hostname.endsWith(tld); });
    if (hasSuspiciousTld) {
      signals.push({ type: 'warning', label: 'URL Analysis', value: 'Uses a TLD commonly associated with free or malicious domains' });
      score += 20;
    }

    // 5. Excessive subdomains (more than 3 dots = phishing trick like paypal.com.fake.net)
    var dots = (hostname.match(/\./g) || []).length;
    if (dots >= 3) {
      signals.push({ type: 'warning', label: 'URL Analysis', value: 'Excessive subdomains detected — common phishing trick (e.g. paypal.com.evil.net)' });
      score += 25;
    }

    // 6. Very long URL
    if (url.length > 100) {
      signals.push({ type: 'warning', label: 'URL Analysis', value: 'Unusually long URL (' + url.length + ' characters)' });
      score += 10;
    }

    // 7. Brand name in subdomain (not the real domain)
    var brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix',
      'facebook', 'instagram', 'twitter', 'chase', 'coinbase', 'binance',
      'mercadolibre', 'ebay', 'walmart', 'bancolombia', 'banregio'];
    var foundBrand = brands.find(function(b) { return fullUrl.includes(b); });
    if (foundBrand && !registeredDomain.startsWith(foundBrand)) {
      signals.push({ type: 'danger', label: 'Brand in Subdomain', value: '"' + foundBrand + '" appears in subdomain or path — not the real site' });
      score += 35;
    }

    // 8. Brand + dangerous keyword combination
    var dangerKeywords = ['login', 'verify', 'secure', 'account', 'update',
      'confirm', 'alert', 'suspend', 'password', 'signin', 'banking', 'validate'];
    var foundKeyword = dangerKeywords.find(function(k) { return fullUrl.includes(k); });
    if (foundBrand && foundKeyword) {
      signals.push({ type: 'warning', label: 'URL Analysis', value: 'Suspicious combination: brand name + action keyword ("' + foundKeyword + '")' });
      score += 15;
    }

    // 9. Typosquatting — known misspellings of major brands
    var typoMap = {
      'paypal':    ['paypa1', 'paypall', 'paypa-l', 'pay-pal', 'paypel', 'payapl'],
      'google':    ['googie', 'g00gle', 'gooogle', 'googel', 'gogle'],
      'amazon':    ['amazom', 'arnazon', 'amaz0n', 'amazone', 'amzon'],
      'microsoft': ['micros0ft', 'microsofl', 'micosoft', 'microsofft'],
      'apple':     ['app1e', 'appie', 'aple', 'aplle'],
      'facebook':  ['faceb00k', 'facebok', 'faceboook', 'facbook'],
      'netflix':   ['netfl1x', 'netfiix', 'netlfix', 'netfliix'],
      'coinbase':  ['co1nbase', 'coinbas3', 'coinbasse'],
      'binance':   ['b1nance', 'binanse', 'binanc3'],
      'instagram': ['1nstagram', 'instagran', 'instagarm']
    };
    var foundTypo = null;
    Object.keys(typoMap).forEach(function(brand) {
      typoMap[brand].forEach(function(typo) {
        if (hostname.includes(typo)) foundTypo = brand;
      });
    });
    if (foundTypo) {
      signals.push({ type: 'danger', label: 'Typosquatting', value: 'Domain mimics "' + foundTypo + '" using a common spelling trick' });
      score += 40;
    }

    if (signals.length === 0) {
      signals.push({ type: 'safe', label: 'URL Analysis', value: 'No suspicious URL patterns detected' });
    }

  } catch(e) {
    signals.push({ type: 'warning', label: 'URL Analysis', value: 'Could not parse URL structure' });
    score += 10;
  }

  return { signals: signals, score: score };
}

// ─── SSL CHECK ───────────────────────────────────────────────────────────────

function checkSsl(url) {
  return new Promise(function(resolve) {
    try {
      var parsed = new URL(url);
      if (parsed.protocol !== 'https:') {
        resolve({ signals: [{ type: 'danger', label: 'SSL Certificate', value: 'Site does not use HTTPS' }], score: 30 });
        return;
      }
      var options = {
        hostname: parsed.hostname,
        port: 443,
        path: '/',
        method: 'GET',
        timeout: 5000,
        rejectUnauthorized: false
      };
      var req = https.request(options, function(response) {
        try {
          var cert = response.socket.getPeerCertificate();
          if (!cert || !cert.valid_from) { resolve({ signals: [], score: 0 }); return; }
          var issuedDate = new Date(cert.valid_from);
          var daysSinceIssued = Math.floor((new Date() - issuedDate) / (1000 * 60 * 60 * 24));
          var issuer = cert.issuer && cert.issuer.O ? cert.issuer.O : '';
          var freeIssuers = ["Let's Encrypt", 'ZeroSSL', 'Buypass'];
          var isFreeIssuer = freeIssuers.some(function(f) { return issuer.includes(f); });
          var signals = [];
          var score = 0;
          if (daysSinceIssued < 30 && isFreeIssuer) {
            signals.push({ type: 'warning', label: 'SSL Certificate', value: 'Certificate issued recently (' + daysSinceIssued + ' days ago) by free provider — common in phishing sites' });
            score += 20;
          } else if (daysSinceIssued < 7) {
            signals.push({ type: 'warning', label: 'SSL Certificate', value: 'Certificate issued only ' + daysSinceIssued + ' days ago' });
            score += 15;
          } else {
            signals.push({ type: 'safe', label: 'SSL Certificate', value: 'Valid certificate from ' + (issuer || 'trusted issuer') });
          }
          resolve({ signals: signals, score: score });
        } catch(e) { resolve({ signals: [], score: 0 }); }
      });
      req.on('timeout', function() { req.destroy(); resolve({ signals: [], score: 0 }); });
      req.on('error', function() {
        resolve({ signals: [{ type: 'warning', label: 'SSL Certificate', value: 'Could not verify SSL certificate' }], score: 15 });
      });
      req.end();
    } catch(e) { resolve({ signals: [], score: 0 }); }
  });
}

// ─── REDIRECT CHECK ──────────────────────────────────────────────────────────

function checkRedirects(url) {
  return new Promise(function(resolve) {
    var redirectCount = 0;
    var maxRedirects = 6;

    function followRedirect(currentUrl) {
      try {
        var parsed = new URL(currentUrl);
        var lib = parsed.protocol === 'https:' ? https : http;
        var options = {
          hostname: parsed.hostname,
          port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
          path: (parsed.pathname || '/') + (parsed.search || ''),
          method: 'HEAD',
          timeout: 5000,
          headers: { 'User-Agent': 'Mozilla/5.0' },
          rejectUnauthorized: false
        };
        var req = lib.request(options, function(response) {
          if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
            redirectCount++;
            if (redirectCount >= maxRedirects) {
              resolve({ signals: [{ type: 'danger', label: 'Redirections', value: 'Too many redirects — suspicious behavior' }], score: 25 });
              return;
            }
            var nextUrl = response.headers.location;
            if (!nextUrl.startsWith('http')) nextUrl = parsed.origin + nextUrl;
            followRedirect(nextUrl);
          } else {
            if (redirectCount > 2) {
              resolve({ signals: [{ type: 'warning', label: 'Redirections', value: redirectCount + ' redirects before reaching destination — suspicious' }], score: 20 });
            } else if (redirectCount > 0) {
              resolve({ signals: [{ type: 'safe', label: 'Redirections', value: redirectCount + ' redirect(s) — within normal range' }], score: 0 });
            } else {
              resolve({ signals: [{ type: 'safe', label: 'Redirections', value: 'No redirects detected' }], score: 0 });
            }
          }
        });
        req.on('timeout', function() { req.destroy(); resolve({ signals: [], score: 0 }); });
        req.on('error', function() { resolve({ signals: [], score: 0 }); });
        req.end();
      } catch(e) { resolve({ signals: [], score: 0 }); }
    }

    followRedirect(url);
  });
}

// ─── WHITELIST ───────────────────────────────────────────────────────────────

async function isWhitelisted(email, url) {
  if (!email) return false;
  try {
    var domain = new URL(url).hostname.replace('www.', '');
    var result = await supabaseRequest('GET', 'whitelist?email=eq.' + encodeURIComponent(email) + '&domain=eq.' + encodeURIComponent(domain) + '&select=*');
    return result && result.length > 0;
  } catch(e) { return false; }
}

app.get('/whitelist/:email', async function(req, res) {
  var email = req.params.email;
  if (!email) return res.status(400).json({ error: 'Email required' });
  var result = await supabaseRequest('GET', 'whitelist?email=eq.' + encodeURIComponent(email) + '&select=*');
  res.json(result || []);
});

app.post('/whitelist/add', async function(req, res) {
  var email = req.body.email;
  var url = req.body.url;
  if (!email || !url) return res.status(400).json({ error: 'Email and URL required' });
  try {
    var domain = new URL(url).hostname.replace('www.', '');
    var existing = await supabaseRequest('GET', 'whitelist?email=eq.' + encodeURIComponent(email) + '&domain=eq.' + encodeURIComponent(domain) + '&select=*');
    if (existing && existing.length > 0) return res.json({ success: true, message: 'Already in whitelist' });
    await supabaseRequest('POST', 'whitelist', { email: email, domain: domain });
    res.json({ success: true, domain: domain });
  } catch(e) { res.status(400).json({ error: 'Invalid URL' }); }
});

app.post('/whitelist/remove', async function(req, res) {
  var email = req.body.email;
  var domain = req.body.domain;
  if (!email || !domain) return res.status(400).json({ error: 'Email and domain required' });
  await supabaseRequest('DELETE', 'whitelist?email=eq.' + encodeURIComponent(email) + '&domain=eq.' + encodeURIComponent(domain));
  res.json({ success: true });
});

// ─── ANALYZE (web app) ──────────────────────────────────────────────────────

app.post('/analyze', async function(req, res) {
  var url = req.body.url;
  var screenshot = req.body.screenshot;
  var imageType = req.body.imageType || 'image/jpeg';
  var email = req.body.email || null;
  var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';

  if (!url && !screenshot) return res.status(400).json({ error: 'URL or screenshot required' });

  if (email) {
    var user = await getUserTokens(email);
    if (!user) return res.status(403).json({ error: 'User not found. Please register first.' });
    if (user.tokens < 5) return res.status(403).json({ error: 'Not enough NekoTokens. Please purchase more.', tokens: user.tokens });
  }

  try {
    var results = { url: url || 'screenshot', score: 0, signals: [], verdict: 'safe', brand: null };

    if (url) {
      // Check whitelist first
      if (email && await isWhitelisted(email, url)) {
        results.signals.push({ type: 'safe', label: 'Whitelist', value: 'Domain is in your trusted list' });
        results.verdict = 'safe';
        if (email) await deductToken(email);
        return res.json(results);
      }

      // Run all checks in parallel (except AI which runs conditionally after)
      var checks = await Promise.allSettled([
        Promise.resolve(analyzeUrlPattern(url)),
        checkGoogleSafeBrowsing(url),
        checkWhois(url),
        checkSsl(url),
        checkRedirects(url)
      ]);

      checks.forEach(function(check) {
        if (check.status === 'fulfilled' && check.value) {
          (check.value.signals || []).forEach(function(s) { results.signals.push(s); });
          results.score += check.value.score || 0;
          if (check.value.brand) results.brand = check.value.brand;
          if (check.value.explanation) results.explanation = check.value.explanation;
          if (check.value.domainAge) results.domainAge = check.value.domainAge;
        }
      });

      results.score = Math.min(100, results.score);

      // AI only if score is ambiguous (20-69)
      if (results.score >= 20 && results.score < 70) {
        var aiResult = await analyzeWithAI(url, null, null);
        (aiResult.signals || []).forEach(function(s) { results.signals.push(s); });
        results.score += aiResult.score || 0;
        if (aiResult.brand) results.brand = aiResult.brand;
        if (aiResult.explanation) results.explanation = aiResult.explanation;
        results.score = Math.min(100, results.score);
      }

    } else {
      // Screenshot analysis always uses AI
      var aiResult = await analyzeWithAI(null, screenshot, imageType);
      (aiResult.signals || []).forEach(function(s) { results.signals.push(s); });
      results.score += aiResult.score || 0;
      results.brand = aiResult.brand;
      results.explanation = aiResult.explanation;
    }

    results.score = Math.min(100, results.score);
    if (results.score >= 70) results.verdict = 'dangerous';
    else if (results.score >= 40) results.verdict = 'suspicious';

    if (email) await deductToken(email);
    await saveAnalysis(email, ip, url ? 'url' : 'screenshot', results.verdict, results.score, results.brand, url);

    if (email) {
      var updatedUser = await getUserTokens(email);
      results.tokensRemaining = updatedUser ? updatedUser.tokens : null;
    }

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Analysis failed', message: error.message });
  }
});

// ─── GOOGLE SAFE BROWSING ───────────────────────────────────────────────────

function checkGoogleSafeBrowsing(url) {
  return new Promise(function(resolve) {
    if (!GOOGLE_API_KEY) { resolve({ signals: [], score: 0 }); return; }
    var bodyData = JSON.stringify({
      client: { clientId: 'nekoshield', clientVersion: '1.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: url }]
      }
    });
    var options = {
      hostname: 'safebrowsing.googleapis.com',
      path: '/v4/threatMatches:find?key=' + GOOGLE_API_KEY,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyData) }
    };
    var req = https.request(options, function(response) {
      var data = '';
      response.on('data', function(chunk) { data += chunk; });
      response.on('end', function() {
        try {
          var parsed = JSON.parse(data);
          if (parsed.matches && parsed.matches.length > 0) {
            resolve({ signals: [{ type: 'danger', label: 'Google Safe Browsing', value: 'Listed as dangerous site' }], score: 60 });
          } else {
            resolve({ signals: [{ type: 'safe', label: 'Google Safe Browsing', value: 'Not in blacklist' }], score: 0 });
          }
        } catch(e) { resolve({ signals: [], score: 0 }); }
      });
    });
    req.on('error', function() { resolve({ signals: [], score: 0 }); });
    req.write(bodyData);
    req.end();
  });
}

// ─── WHOIS ──────────────────────────────────────────────────────────────────

function checkWhois(url) {
  return new Promise(function(resolve) {
    try {
      var domain = new URL(url).hostname.replace('www.', '');
      var options = {
        hostname: 'api.whoisfreaks.com',
        path: '/v1.0/whois?apiKey=free&whois=live&domainName=' + domain,
        method: 'GET'
      };
      var req = https.request(options, function(response) {
        var data = '';
        response.on('data', function(chunk) { data += chunk; });
        response.on('end', function() {
          try {
            var parsed = JSON.parse(data);
            var createdDate = parsed.create_date || parsed.domain_registered_at;
            if (createdDate) {
              var daysDiff = Math.floor((new Date() - new Date(createdDate)) / (1000 * 60 * 60 * 24));
              if (daysDiff < 7) {
                resolve({ signals: [{ type: 'danger', label: 'Domain Age', value: 'Registered only ' + daysDiff + ' days ago' }], score: 35, domainAge: daysDiff + ' days' });
              } else if (daysDiff < 30) {
                resolve({ signals: [{ type: 'warning', label: 'Domain Age', value: 'Registered ' + daysDiff + ' days ago' }], score: 20, domainAge: daysDiff + ' days' });
              } else {
                resolve({ signals: [{ type: 'safe', label: 'Domain Age', value: Math.floor(daysDiff/365) + ' years old' }], score: 0, domainAge: Math.floor(daysDiff/365) + ' years' });
              }
            } else {
              resolve({ signals: [], score: 0, domainAge: null });
            }
          } catch(e) { resolve({ signals: [], score: 0, domainAge: null }); }
        });
      });
      req.on('error', function() { resolve({ signals: [], score: 0, domainAge: null }); });
      req.end();
    } catch(e) { resolve({ signals: [], score: 0, domainAge: null }); }
  });
}

// ─── AI ANALYSIS ────────────────────────────────────────────────────────────

function analyzeWithAI(url, screenshot, imageType) {
  imageType = imageType || 'image/jpeg';
  return new Promise(function(resolve) {
    if (!ANTHROPIC_API_KEY) { resolve({ signals: [], score: 0, brand: null, explanation: null }); return; }
    var content = [];
    if (screenshot) {
      content = [
        { type: 'image', source: { type: 'base64', media_type: imageType, data: screenshot } },
        { type: 'text', text: 'You are NekoShield, a phishing detection AI. Analyze this screenshot for phishing threats. Look for fake brand logos, suspicious URLs, urgency tactics, requests for credentials. Respond ONLY with valid JSON no markdown: {"isPhishing": true, "confidence": 95, "brand": "PayPal", "detectedUrl": "http://fake.com", "reasons": ["reason1"], "explanation": "one sentence"}' }
      ];
    } else {
      content = [
        { type: 'text', text: 'You are NekoShield, an aggressive phishing detection AI. Analyze this URL: ' + url + '\n\nCheck for:\n1. Brand names (PayPal, Amazon, Coinbase, Chase, Apple, Microsoft, Netflix, Mercado Libre, Binance, Bank of America) in domains that are NOT the official domain\n2. Suspicious words: secure, verify, login, account, update, confirm, alert, suspend, cancel combined with brand names\n3. Typosquatting\n4. Subdomain tricks like paypal.com.fake-site.net\n5. Suspicious TLDs: .net .info .xyz .online for financial sites\n\nBe AGGRESSIVE. If ANY brand name appears in a non-official domain, mark as phishing.\n\nRespond ONLY with valid JSON no markdown: {"isPhishing": true, "confidence": 95, "brand": "PayPal", "reasons": ["reason1", "reason2"], "explanation": "one sentence plain english"}' }
      ];
    }
    var bodyData = JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 500, messages: [{ role: 'user', content: content }] });
    var options = {
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'Content-Length': Buffer.byteLength(bodyData) }
    };
    var req = https.request(options, function(response) {
      var data = '';
      response.on('data', function(chunk) { data += chunk; });
      response.on('end', function() {
        try {
          var parsed = JSON.parse(data);
          var text = parsed.content[0].text;
          var clean = text.replace(/```json/g, '').replace(/```/g, '').trim();
          var aiResult = JSON.parse(clean);
          var signals = [];
          var score = 0;
          if (aiResult.brand) {
            signals.push({ type: 'danger', label: 'Brand Impersonation', value: 'Imitating ' + aiResult.brand + ' (' + aiResult.confidence + '% confidence)' });
            score += Math.floor(aiResult.confidence * 0.4);
          }
          if (aiResult.reasons) {
            aiResult.reasons.forEach(function(reason) {
              signals.push({ type: aiResult.isPhishing ? 'warning' : 'safe', label: 'AI Detection', value: reason });
            });
          }
          if (!aiResult.isPhishing) signals.push({ type: 'safe', label: 'AI Analysis', value: 'No phishing patterns detected' });
          resolve({ signals: signals, score: aiResult.isPhishing ? Math.max(score, 30) : 0, brand: aiResult.brand, explanation: aiResult.explanation, detectedUrl: aiResult.detectedUrl });
        } catch(e) {
          resolve({ signals: [], score: 0, brand: null, explanation: null });
        }
      });
    });
    req.on('error', function() { resolve({ signals: [], score: 0, brand: null, explanation: null }); });
    req.write(bodyData);
    req.end();
  });
}

// ─── WHATSAPP BOT ───────────────────────────────────────────────────────────

app.post('/whatsapp', async function(req, res) {
  var TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
  var TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
  var TWILIO_WHATSAPP_NUMBER = process.env.TWILIO_WHATSAPP_NUMBER;
  var incomingMsg = req.body.Body || '';
  var fromNumber = req.body.From || '';
  var numMedia = parseInt(req.body.NumMedia || '0');
  var replyText = '';

  try {
    if (numMedia > 0) {
      var mediaUrl = req.body.MediaUrl0;
      var mediaType = req.body.MediaContentType0 || 'image/jpeg';
      var imageBase64 = await downloadImageAsBase64(mediaUrl, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
      if (imageBase64) {
        var analysis = await analyzeWithAI(null, imageBase64, mediaType);
        replyText = formatWhatsAppReply({ signals: analysis.signals, score: Math.min(100, analysis.score), brand: analysis.brand, explanation: analysis.explanation, verdict: analysis.score >= 70 ? 'dangerous' : analysis.score >= 40 ? 'suspicious' : 'safe' }, null);
      } else {
        replyText = '⚠️ Could not process the image. Please try again.';
      }
    } else if (incomingMsg.trim()) {
      var msg = incomingMsg.trim();
      if (msg.startsWith('http://') || msg.startsWith('https://') || msg.includes('.com') || msg.includes('.net') || msg.includes('.org')) {
        var url = msg;
        if (!url.startsWith('http')) url = 'https://' + url;
        var checks = await Promise.allSettled([
          Promise.resolve(analyzeUrlPattern(url)),
          checkGoogleSafeBrowsing(url),
          checkWhois(url),
          checkSsl(url),
          checkRedirects(url)
        ]);
        var combinedResult = { score: 0, signals: [], brand: null, explanation: null, verdict: 'safe' };
        checks.forEach(function(check) {
          if (check.status === 'fulfilled' && check.value) {
            (check.value.signals || []).forEach(function(s) { combinedResult.signals.push(s); });
            combinedResult.score += check.value.score || 0;
            if (check.value.brand) combinedResult.brand = check.value.brand;
            if (check.value.explanation) combinedResult.explanation = check.value.explanation;
          }
        });
        combinedResult.score = Math.min(100, combinedResult.score);
        // AI only if ambiguous
        if (combinedResult.score >= 20 && combinedResult.score < 70) {
          var aiResult = await analyzeWithAI(url, null, null);
          (aiResult.signals || []).forEach(function(s) { combinedResult.signals.push(s); });
          combinedResult.score += aiResult.score || 0;
          if (aiResult.brand) combinedResult.brand = aiResult.brand;
          if (aiResult.explanation) combinedResult.explanation = aiResult.explanation;
          combinedResult.score = Math.min(100, combinedResult.score);
        }
        if (combinedResult.score >= 70) combinedResult.verdict = 'dangerous';
        else if (combinedResult.score >= 40) combinedResult.verdict = 'suspicious';
        replyText = formatWhatsAppReply(combinedResult, url);
      } else if (['help', 'hola', 'hi', 'hello', 'start'].includes(msg.toLowerCase())) {
        replyText = '🛡️ *NekoShield* — Phishing Detection\n\nSend me:\n• A suspicious *link* to analyze it\n• A *screenshot* of a suspicious message\n\nI will tell you if it\'s safe or dangerous! 🐱\n\n_nekoshield.com_';
      } else {
        replyText = '🛡️ *NekoShield* here!\n\nSend me a suspicious *link* or a *screenshot* of a message and I\'ll analyze it.\n\nType *help* for more info.';
      }
    } else {
      replyText = '🛡️ *NekoShield* here! Send me a link or screenshot to analyze.';
    }
  } catch (error) {
    replyText = '⚠️ Something went wrong. Please try again.';
  }

  await sendWhatsAppReply(fromNumber, replyText, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_NUMBER);
  res.status(200).send('OK');
});

function formatWhatsAppReply(analysis, url) {
  var verdict = analysis.verdict || 'safe';
  var score = Math.min(100, analysis.score || 0);
  var reply = '';
  if (verdict === 'dangerous') {
    reply = '🚨 *HIGH RISK — Do NOT proceed*\nThreat Level: ' + score + '%\n\n';
  } else if (verdict === 'suspicious') {
    reply = '⚠️ *SUSPICIOUS — Proceed with caution*\nThreat Level: ' + score + '%\n\n';
  } else {
    reply = '✅ *SECURE — No threats detected*\n\n';
  }
  if (analysis.brand) reply += '🎭 Impersonating: *' + analysis.brand + '*\n';
  if (analysis.explanation) reply += '📋 ' + analysis.explanation + '\n';
  reply += '\n_Analyzed by NekoShield • nekoshield.com_';
  return reply;
}

function downloadImageAsBase64(mediaUrl, accountSid, authToken) {
  return new Promise(function(resolve) {
    var auth = Buffer.from(accountSid + ':' + authToken).toString('base64');
    var urlObj = new URL(mediaUrl);
    var options = { hostname: urlObj.hostname, path: urlObj.pathname + urlObj.search, method: 'GET', headers: { 'Authorization': 'Basic ' + auth } };
    var req = https.request(options, function(response) {
      var chunks = [];
      response.on('data', function(chunk) { chunks.push(chunk); });
      response.on('end', function() { resolve(Buffer.concat(chunks).toString('base64')); });
    });
    req.on('error', function() { resolve(null); });
    req.end();
  });
}

function sendWhatsAppReply(to, body, accountSid, authToken, fromNumber) {
  return new Promise(function(resolve) {
    if (!accountSid || !authToken || !fromNumber) { resolve(); return; }
    var postData = 'To=' + encodeURIComponent(to) + '&From=' + encodeURIComponent('whatsapp:' + fromNumber) + '&Body=' + encodeURIComponent(body);
    var auth = Buffer.from(accountSid + ':' + authToken).toString('base64');
    var options = {
      hostname: 'api.twilio.com',
      path: '/2010-04-01/Accounts/' + accountSid + '/Messages.json',
      method: 'POST',
      headers: { 'Authorization': 'Basic ' + auth, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(postData) }
    };
    var req = https.request(options, function(response) {
      var data = '';
      response.on('data', function(chunk) { data += chunk; });
      response.on('end', function() { resolve(); });
    });
    req.on('error', function() { resolve(); });
    req.write(postData);
    req.end();
  });
}

// ─── PAYPAL ─────────────────────────────────────────────────────────────────

async function getPaypalToken() {
  return new Promise(function(resolve) {
    var auth = Buffer.from(PAYPAL_CLIENT_ID + ':' + PAYPAL_SECRET).toString('base64');
    var body = 'grant_type=client_credentials';
    var options = {
      hostname: 'api-m.paypal.com',
      path: '/v1/oauth2/token',
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + auth,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body)
      }
    };
    var req = https.request(options, function(response) {
      var data = '';
      response.on('data', function(chunk) { data += chunk; });
      response.on('end', function() {
        try { resolve(JSON.parse(data).access_token); }
        catch(e) { resolve(null); }
      });
    });
    req.on('error', function() { resolve(null); });
    req.write(body);
    req.end();
  });
}

app.post('/create-order', async function(req, res) {
  var plan = req.body.plan;
  var email = req.body.email;

  var plans = {
    starter: { amount: '4.99', tokens: 100, name: 'NekoShield Starter — 100 NekoTokens' },
    pro:     { amount: '14.99', tokens: 500, name: 'NekoShield Pro — 500 NekoTokens' },
    business:{ amount: '19.99', tokens: 1000, name: 'NekoShield Business — 1,000 NekoTokens' }
  };

  var selected = plans[plan];
  if (!selected) return res.status(400).json({ error: 'Invalid plan' });

  var token = await getPaypalToken();
  if (!token) return res.status(500).json({ error: 'PayPal auth failed' });

  var orderBody = JSON.stringify({
    intent: 'CAPTURE',
    purchase_units: [{
      amount: { currency_code: 'USD', value: selected.amount },
      description: selected.name,
      custom_id: email + '|' + plan
    }],
    application_context: {
      return_url: 'https://nekoshield.com',
      cancel_url: 'https://nekoshield.com'
    }
  });

  var options = {
    hostname: 'api-m.paypal.com',
    path: '/v2/checkout/orders',
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(orderBody)
    }
  };

  var req2 = https.request(options, function(response) {
    var data = '';
    response.on('data', function(chunk) { data += chunk; });
    response.on('end', function() {
      try {
        var order = JSON.parse(data);
        var approveUrl = order.links.find(function(l) { return l.rel === 'approve'; });
        res.json({ orderID: order.id, approveUrl: approveUrl ? approveUrl.href : null });
      } catch(e) { res.status(500).json({ error: 'Order creation failed' }); }
    });
  });
  req2.on('error', function() { res.status(500).json({ error: 'Request failed' }); });
  req2.write(orderBody);
  req2.end();
});

app.post('/capture-order', async function(req, res) {
  var orderID = req.body.orderID;
  var email = req.body.email;

  var token = await getPaypalToken();
  if (!token) return res.status(500).json({ error: 'PayPal auth failed' });

  var options = {
    hostname: 'api-m.paypal.com',
    path: '/v2/checkout/orders/' + orderID + '/capture',
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json',
      'Content-Length': 0
    }
  };

  var req2 = https.request(options, function(response) {
    var data = '';
    response.on('data', function(chunk) { data += chunk; });
    response.on('end', async function() {
      try {
        var capture = JSON.parse(data);
        if (capture.status === 'COMPLETED') {
          var customId = capture.purchase_units[0].payments.captures[0].custom_id;
          var parts = customId.split('|');
          var userEmail = parts[0];
          var plan = parts[1];
          var tokensMap = { starter: 100, pro: 500, business: 1000 };
          var tokensToAdd = tokensMap[plan] || 0;

          var user = await getUserTokens(userEmail);
          if (user) {
            await supabaseRequest('PATCH', 'user_tokens?email=eq.' + encodeURIComponent(userEmail), {
              tokens: user.tokens + tokensToAdd
            });
          }
          res.json({ success: true, tokensAdded: tokensToAdd });
        } else {
          res.status(400).json({ error: 'Payment not completed' });
        }
      } catch(e) { res.status(500).json({ error: 'Capture failed' }); }
    });
  });
  req2.on('error', function() { res.status(500).json({ error: 'Request failed' }); });
  req2.end();
});

// ─── EXTENSION ANALYZE ──────────────────────────────────────────────────────

async function checkOpenPhish(url) {
  return new Promise(function(resolve) {
    var options = {
      hostname: 'openphish.com',
      path: '/feed.txt',
      method: 'GET'
    };
    var req = https.request(options, function(response) {
      var data = '';
      response.on('data', function(chunk) { data += chunk; });
      response.on('end', function() {
        var lines = data.split('\n');
        var found = lines.some(function(line) {
          return line.trim() && url.includes(line.trim());
        });
        if (found) {
          resolve({ signals: [{ type: 'danger', label: 'OpenPhish', value: 'Listed as active phishing site' }], score: 80 });
        } else {
          resolve({ signals: [{ type: 'safe', label: 'OpenPhish', value: 'Not in phishing database' }], score: 0 });
        }
      });
    });
    req.on('error', function() { resolve({ signals: [], score: 0 }); });
    req.end();
  });
}

app.post('/extension-analyze', async function(req, res) {
  var url = req.body.url;
  var email = req.body.email || null;
  if (!url) return res.status(400).json({ error: 'URL required' });

  try {
    var results = { url: url, score: 0, signals: [], verdict: 'safe' };

    // Step 0: Check whitelist first
    if (email && await isWhitelisted(email, url)) {
      results.signals.push({ type: 'safe', label: 'Whitelist', value: 'Domain is in your trusted list' });
      return res.json(results);
    }

    // Step 1: Check our own Supabase database (cache)
    var ownDbResult = await checkOwnDatabase(url);
    if (ownDbResult) {
      ownDbResult.signals.forEach(function(s) { results.signals.push(s); });
      results.score += ownDbResult.score || 0;
      results.score = Math.min(100, results.score);
      if (results.score >= 70) results.verdict = 'dangerous';
      else if (results.score >= 40) results.verdict = 'suspicious';
      return res.json(results);
    }

    // Step 2: Run all fast checks in parallel
    var checks = await Promise.allSettled([
      Promise.resolve(analyzeUrlPattern(url)),
      checkGoogleSafeBrowsing(url),
      checkOpenPhish(url),
      checkWhois(url),
      checkSsl(url),
      checkRedirects(url)
    ]);

    checks.forEach(function(check) {
      if (check.status === 'fulfilled' && check.value) {
        (check.value.signals || []).forEach(function(s) { results.signals.push(s); });
        results.score += check.value.score || 0;
        if (check.value.brand) results.brand = check.value.brand;
        if (check.value.domainAge) results.domainAge = check.value.domainAge;
      }
    });

    results.score = Math.min(100, results.score);

    // Step 3: AI only if score is ambiguous (20-69)
    if (results.score >= 20 && results.score < 70) {
      var aiResult = await analyzeWithAI(url, null, null);
      (aiResult.signals || []).forEach(function(s) { results.signals.push(s); });
      results.score += aiResult.score || 0;
      if (aiResult.explanation) results.explanation = aiResult.explanation;
      if (aiResult.brand) results.brand = aiResult.brand;
      results.score = Math.min(100, results.score);
    }

    if (results.score >= 70) results.verdict = 'dangerous';
    else if (results.score >= 40) results.verdict = 'suspicious';

    // Save to Supabase (now with URL so cache works correctly)
    await saveAnalysis(email, 'extension', 'url', results.verdict, results.score, results.brand, url);

    res.json(results);

  } catch(error) {
    res.status(500).json({ error: 'Analysis failed' });
  }
});

// ─── START ──────────────────────────────────────────────────────────────────

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('NekoShield API running on port ' + PORT);
  console.log('GOOGLE_API_KEY: ' + !!GOOGLE_API_KEY);
  console.log('ANTHROPIC_API_KEY: ' + !!ANTHROPIC_API_KEY);
  console.log('SUPABASE_URL: ' + !!SUPABASE_URL);
});
