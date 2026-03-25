const express = require('express');
const cors = require('cors');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

app.get('/', (req, res) => {
  res.json({ 
    status: 'NekoShield API running 🛡️',
    hasGoogle: !!GOOGLE_API_KEY,
    hasAnthropic: !!ANTHROPIC_API_KEY,
    googleLength: GOOGLE_API_KEY ? GOOGLE_API_KEY.length : 0,
    anthropicLength: ANTHROPIC_API_KEY ? ANTHROPIC_API_KEY.length : 0
  });
});
```

Commit, espera el redeploy y luego abre:
```
https://nekoshield-server-production.up.railway.app

app.post('/analyze', async (req, res) => {
  const { url, screenshot } = req.body;
  if (!url && !screenshot) {
    return res.status(400).json({ error: 'URL or screenshot required' });
  }
  try {
    let results = { url: url || 'screenshot', score: 0, signals: [], verdict: 'safe', brand: null };

    if (url) {
      const [safeBrowsing, whois, aiAnalysis] = await Promise.allSettled([
        checkGoogleSafeBrowsing(url),
        checkWhois(url),
        analyzeWithAI(url, null)
      ]);
      if (safeBrowsing.status === 'fulfilled') { results.signals.push(...safeBrowsing.value.signals); results.score += safeBrowsing.value.score; }
      if (whois.status === 'fulfilled') { results.signals.push(...whois.value.signals); results.score += whois.value.score; results.domainAge = whois.value.domainAge; }
      if (aiAnalysis.status === 'fulfilled') { results.signals.push(...aiAnalysis.value.signals); results.score += aiAnalysis.value.score; results.brand = aiAnalysis.value.brand; results.explanation = aiAnalysis.value.explanation; }
    } else if (screenshot) {
      const aiAnalysis = await analyzeWithAI(null, screenshot);
      results.signals.push(...aiAnalysis.signals);
      results.score += aiAnalysis.score;
      results.brand = aiAnalysis.brand;
      results.explanation = aiAnalysis.explanation;
    }

    results.score = Math.min(100, results.score);
    if (results.score >= 70) results.verdict = 'dangerous';
    else if (results.score >= 40) results.verdict = 'suspicious';
    else results.verdict = 'safe';

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Analysis failed' });
  }
});

async function checkGoogleSafeBrowsing(url) {
  return new Promise((resolve) => {
    if (!GOOGLE_API_KEY) { resolve({ signals: [], score: 0 }); return; }
    const body = JSON.stringify({
      client: { clientId: 'nekoshield', clientVersion: '1.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }]
      }
    });
    const options = {
      hostname: 'safebrowsing.googleapis.com',
      path: '/v4/threatMatches:find?key=' + GOOGLE_API_KEY,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    };
    const req = https.request(options, (response) => {
      let data = '';
      response.on('data', chunk => data += chunk);
      response.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.matches && parsed.matches.length > 0) {
            resolve({ signals: [{ type: 'danger', label: 'Google Safe Browsing', value: 'Listed as dangerous site' }], score: 60 });
          } else {
            resolve({ signals: [{ type: 'safe', label: 'Google Safe Browsing', value: 'Not in blacklist' }], score: 0 });
          }
        } catch { resolve({ signals: [], score: 0 }); }
      });
    });
    req.on('error', () => resolve({ signals: [], score: 0 }));
    req.write(body);
    req.end();
  });
}

async function checkWhois(url) {
  return new Promise((resolve) => {
    try {
      const domain = new URL(url).hostname.replace('www.', '');
      const options = {
        hostname: 'api.whoisfreaks.com',
        path: '/v1.0/whois?apiKey=free&whois=live&domainName=' + domain,
        method: 'GET'
      };
      const req = https.request(options, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            const createdDate = parsed.create_date || parsed.domain_registered_at;
            if (createdDate) {
              const daysDiff = Math.floor((new Date() - new Date(createdDate)) / (1000 * 60 * 60 * 24));
              if (daysDiff < 7) {
                resolve({ signals: [{ type: 'danger', label: 'Domain Age', value: 'Registered only ' + daysDiff + ' days ago' }], score: 35, domainAge: daysDiff + ' days' });
              } else if (daysDiff < 30) {
                resolve({ signals: [{ type: 'warning', label: 'Domain Age', value: 'Registered ' + daysDiff + ' days ago' }], score: 20, domainAge: daysDiff + ' days' });
              } else {
                resolve({ signals: [{ type: 'safe', label: 'Domain Age', value: Math.floor(daysDiff/365) + ' years old' }], score: 0, domainAge: Math.floor(daysDiff/365) + ' years' });
              }
            } else { resolve({ signals: [], score: 0, domainAge: null }); }
          } catch { resolve({ signals: [], score: 0, domainAge: null }); }
        });
      });
      req.on('error', () => resolve({ signals: [], score: 0, domainAge: null }));
      req.end();
    } catch { resolve({ signals: [], score: 0, domainAge: null }); }
  });
}

async function analyzeWithAI(url, screenshot) {
  return new Promise((resolve) => {
    if (!ANTHROPIC_API_KEY) { resolve({ signals: [], score: 0, brand: null, explanation: null }); return; }

    let content = [];

    if (screenshot) {
      content = [
        { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: screenshot } },
        { type: 'text', text: 'You are NekoShield, a phishing detection AI. Analyze this screenshot for phishing threats. Look for: fake brand logos, suspicious URLs, urgency tactics, requests for credentials. Respond ONLY with valid JSON: {"isPhishing": true/false, "confidence": 0-100, "brand": "brand name or null", "detectedUrl": "any URL visible or null", "reasons": ["reason1"], "explanation": "one sentence explanation"}' }
      ];
    } else {
      content = [
        { type: 'text', text: 'You are NekoShield, an aggressive phishing detection AI. Analyze this URL: ' + url + '\n\nCheck for:\n1. Brand names (PayPal, Amazon, Coinbase, Chase, Apple, Microsoft, Netflix, Mercado Libre, Binance, Bank of America) used in domains that are NOT the official domain\n2. Suspicious words: secure, verify, login, account, update, confirm, alert, suspend, cancel combined with brand names\n3. Typosquatting: paypaI.com, amaz0n.com\n4. Subdomain tricks: paypal.com.fake-site.net (real domain is fake-site.net)\n5. Suspicious TLDs for financial sites: .net .info .xyz .online\n\nBe AGGRESSIVE. If ANY brand name appears in a non-official domain, mark as phishing with high confidence.\n\nRespond ONLY with valid JSON: {"isPhishing": true/false, "confidence": 0-100, "brand": "brand name or null", "reasons": ["reason1", "reason2"], "explanation": "one sentence plain english explanation"}' }
      ];
    }

    const body = JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      messages: [{ role: 'user', content }]
    });

    const options = {
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'Content-Length': Buffer.byteLength(body)
      }
    };

    const req = https.request(options, (response) => {
      let data = '';
      response.on('data', chunk => data += chunk);
      response.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          const text = parsed.content[0].text;
          const clean = text.replace(/```json|```/g, '').trim();
          const aiResult = JSON.parse(clean);
          const signals = [];
          let score = 0;
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
        } catch (e) {
          resolve({ signals: [], score: 0, brand: null, explanation: null });
        }
      });
    });

    req.on('error', () => resolve({ signals: [], score: 0, brand: null, explanation: null }));
    req.write(body);
    req.end();
  });
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, function() { console.log('NekoShield API running on port ' + PORT + '🛡️'); });
