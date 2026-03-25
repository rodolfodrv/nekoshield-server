const express = require('express');
const cors = require('cors');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

app.get('/', function(req, res) {
  res.json({
    status: 'NekoShield API running',
    hasGoogle: !!GOOGLE_API_KEY,
    hasAnthropic: !!ANTHROPIC_API_KEY,
    googleLength: GOOGLE_API_KEY ? GOOGLE_API_KEY.length : 0,
    anthropicLength: ANTHROPIC_API_KEY ? ANTHROPIC_API_KEY.length : 0
  });
});

app.post('/analyze', async function(req, res) {
  const url = req.body.url;
  const screenshot = req.body.screenshot;

  if (!url && !screenshot) {
    return res.status(400).json({ error: 'URL or screenshot required' });
  }

  try {
    var results = { url: url || 'screenshot', score: 0, signals: [], verdict: 'safe', brand: null };

    if (url) {
      var checks = await Promise.allSettled([
        checkGoogleSafeBrowsing(url),
        checkWhois(url),
        analyzeWithAI(url, null)
      ]);

      if (checks[0].status === 'fulfilled') {
        checks[0].value.signals.forEach(function(s) { results.signals.push(s); });
        results.score += checks[0].value.score;
      }
      if (checks[1].status === 'fulfilled') {
        checks[1].value.signals.forEach(function(s) { results.signals.push(s); });
        results.score += checks[1].value.score;
        results.domainAge = checks[1].value.domainAge;
      }
      if (checks[2].status === 'fulfilled') {
        checks[2].value.signals.forEach(function(s) { results.signals.push(s); });
        results.score += checks[2].value.score;
        results.brand = checks[2].value.brand;
        results.explanation = checks[2].value.explanation;
      }
    } else {
      var imageType = req.body.imageType || 'image/jpeg';
      var aiResult = await analyzeWithAI(null, screenshot, imageType);
      aiResult.signals.forEach(function(s) { results.signals.push(s); });
      results.score += aiResult.score;
      results.brand = aiResult.brand;
      results.explanation = aiResult.explanation;
    }

    if (results.score > 100) results.score = 100;
    if (results.score >= 70) results.verdict = 'dangerous';
    else if (results.score >= 40) results.verdict = 'suspicious';
    else results.verdict = 'safe';

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Analysis failed', message: error.message });
  }
});

function checkGoogleSafeBrowsing(url) {
  return new Promise(function(resolve) {
    if (!GOOGLE_API_KEY) {
      resolve({ signals: [{ type: 'warning', label: 'Google Safe Browsing', value: 'API key not configured' }], score: 0 });
      return;
    }
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
        } catch(e) { resolve({ signals: [{ type: 'warning', label: 'Google Safe Browsing', value: 'Parse error: ' + e.message }], score: 0 }); }
      });
    });
    req.on('error', function(e) { resolve({ signals: [{ type: 'warning', label: 'Google Safe Browsing', value: 'Request error: ' + e.message }], score: 0 }); });
    req.write(bodyData);
    req.end();
  });
}

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
              resolve({ signals: [{ type: 'warning', label: 'Domain Age', value: 'Could not determine age' }], score: 0, domainAge: null });
            }
          } catch(e) { resolve({ signals: [{ type: 'warning', label: 'Domain Age', value: 'Lookup error' }], score: 0, domainAge: null }); }
        });
      });
      req.on('error', function(e) { resolve({ signals: [{ type: 'warning', label: 'Domain Age', value: 'Error: ' + e.message }], score: 0, domainAge: null }); });
      req.end();
    } catch(e) { resolve({ signals: [{ type: 'warning', label: 'Domain Age', value: 'Invalid URL' }], score: 0, domainAge: null }); }
  });
}

function analyzeWithAI(url, screenshot, imageType) {
  imageType = imageType || 'image/jpeg';
  return new Promise(function(resolve) {
    if (!ANTHROPIC_API_KEY) {
      resolve({ signals: [{ type: 'warning', label: 'AI Analysis', value: 'API key not configured' }], score: 0, brand: null, explanation: null });
      return;
    }

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

    var bodyData = JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 500,
      messages: [{ role: 'user', content: content }]
    });

    var options = {
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'Content-Length': Buffer.byteLength(bodyData)
      }
    };

    var req = https.request(options, function(response) {
      var data = '';
      response.on('data', function(chunk) { data += chunk; });
      response.on('end', function() {
        try {
          var parsed = JSON.parse(data);
          if (!parsed.content || !parsed.content[0]) {
            resolve({ signals: [{ type: 'warning', label: 'AI Analysis', value: 'No response: ' + JSON.stringify(parsed) }], score: 0, brand: null, explanation: null });
            return;
          }
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
          if (!aiResult.isPhishing) {
            signals.push({ type: 'safe', label: 'AI Analysis', value: 'No phishing patterns detected' });
          }
          resolve({
            signals: signals,
            score: aiResult.isPhishing ? Math.max(score, 30) : 0,
            brand: aiResult.brand,
            explanation: aiResult.explanation,
            detectedUrl: aiResult.detectedUrl
          });
        } catch(e) {
          resolve({ signals: [{ type: 'warning', label: 'AI Analysis', value: 'Parse error: ' + e.message }], score: 0, brand: null, explanation: null });
        }
      });
    });

    req.on('error', function(e) {
      resolve({ signals: [{ type: 'warning', label: 'AI Analysis', value: 'Connection error: ' + e.message }], score: 0, brand: null, explanation: null });
    });
    req.write(bodyData);
    req.end();
  });
}

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('NekoShield API running on port ' + PORT);
  console.log('GOOGLE_API_KEY present: ' + !!GOOGLE_API_KEY);
  console.log('ANTHROPIC_API_KEY present: ' + !!ANTHROPIC_API_KEY);
});
