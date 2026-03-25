const express = require('express');
const cors = require('cors');
const https = require('https');
const http = require('http');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'NekoShield API running 🛡️' });
});

// Analyze URL endpoint
app.post('/analyze', async (req, res) => {
  const { url, screenshot } = req.body;

  if (!url && !screenshot) {
    return res.status(400).json({ error: 'URL or screenshot required' });
  }

  try {
    let results = {
      url: url || 'screenshot analysis',
      score: 0,
      signals: [],
      verdict: 'safe',
      brand: null,
      domainAge: null,
      serverLocation: null
    };

    if (url) {
      // Run all checks in parallel
      const [safeBrowsing, whois, aiAnalysis] = await Promise.allSettled([
        checkGoogleSafeBrowsing(url),
        checkWhois(url),
        analyzeWithAI(url, null)
      ]);

      // Google Safe Browsing
      if (safeBrowsing.status === 'fulfilled') {
        results.signals.push(...safeBrowsing.value.signals);
        results.score += safeBrowsing.value.score;
      }

      // WHOIS domain age
      if (whois.status === 'fulfilled') {
        results.signals.push(...whois.value.signals);
        results.score += whois.value.score;
        results.domainAge = whois.value.domainAge;
      }

      // AI Analysis
      if (aiAnalysis.status === 'fulfilled') {
        results.signals.push(...aiAnalysis.value.signals);
        results.score += aiAnalysis.value.score;
        results.brand = aiAnalysis.value.brand;
        results.explanation = aiAnalysis.value.explanation;
      }

    } else if (screenshot) {
      // Screenshot analysis with Claude
      const aiAnalysis = await analyzeWithAI(null, screenshot);
      results.signals.push(...aiAnalysis.signals);
      results.score += aiAnalysis.score;
      results.brand = aiAnalysis.brand;
      results.explanation = aiAnalysis.explanation;
      results.url = aiAnalysis.detectedUrl || 'detected from screenshot';
    }

    // Cap score at 100
    results.score = Math.min(100, results.score);

    // Determine verdict
    if (results.score >= 70) results.verdict = 'dangerous';
    else if (results.score >= 40) results.verdict = 'suspicious';
    else results.verdict = 'safe';

    res.json(results);

  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: 'Analysis failed', details: error.message });
  }
});

// Google Safe Browsing check
async function checkGoogleSafeBrowsing(url) {
  return new Promise((resolve) => {
    if (!GOOGLE_API_KEY) {
      resolve({ signals: [], score: 0 });
      return;
    }

    const body = JSON.stringify({
      client: { clientId: 'nekoshield', clientVersion: '1.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }]
      }
    });

    const options = {
      hostname: 'safebrowsing.googleapis.com',
      path: `/v4/threatMatches:find?key=${GOOGLE_API_KEY}`,
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
            resolve({
              signals: [{ type: 'danger', label: 'Google Safe Browsing', value: 'Listed as dangerous site' }],
              score: 60
            });
          } else {
            resolve({
              signals: [{ type: 'safe', label: 'Google Safe Browsing', value: 'Not in blacklist' }],
              score: 0
            });
          }
        } catch {
          resolve({ signals: [], score: 0 });
        }
      });
    });

    req.on('error', () => resolve({ signals: [], score: 0 }));
    req.write(body);
    req.end();
  });
}

// WHOIS domain age check
async function checkWhois(url) {
  return new Promise((resolve) => {
    try {
      const domain = new URL(url).hostname.replace('www.', '');

      const options = {
        hostname: 'api.whoisfreaks.com',
        path: `/v1.0/whois?apiKey=free&whois=live&domainName=${domain}`,
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
              const created = new Date(createdDate);
              const now = new Date();
              const daysDiff = Math.floor((now - created) / (1000 * 60 * 60 * 24));

              if (daysDiff < 7) {
                resolve({
                  signals: [{ type: 'danger', label: 'Domain Age', value: `Registered only ${daysDiff} days ago` }],
                  score: 35,
                  domainAge: `${daysDiff} days`
                });
              } else if (daysDiff < 30) {
                resolve({
                  signals: [{ type: 'warning', label: 'Domain Age', value: `Registered ${daysDiff} days ago` }],
                  score: 20,
                  domainAge: `${daysDiff} days`
                });
              } else {
                const years = Math.floor(daysDiff / 365);
                const months = Math.floor((daysDiff % 365) / 30);
                const ageText = years > 0 ? `${years} year${years > 1 ? 's' : ''} old` : `${months} months old`;
                resolve({
                  signals: [{ type: 'safe', label: 'Domain Age', value: ageText }],
                  score: 0,
                  domainAge: ageText
                });
              }
            } else {
              resolve({ signals: [], score: 0, domainAge: null });
            }
          } catch {
            resolve({ signals: [], score: 0, domainAge: null });
          }
        });
      });

      req.on('error', () => resolve({ signals: [], score: 0, domainAge: null }));
      req.end();
    } catch {
      resolve({ signals: [], score: 0, domainAge: null });
    }
  });
}

// Claude AI Analysis
async function analyzeWithAI(url, screenshot) {
  return new Promise((resolve) => {
    if (!ANTHROPIC_API_KEY) {
      resolve({ signals: [], score: 0, brand: null, explanation: null });
      return;
    }

    let content = [];

    if (screenshot) {
      content = [
        {
          type: 'image',
          source: { type: 'base64', media_type: 'image/jpeg', data: screenshot }
        },
        {
          type: 'text',
          text: `You are NekoShield, a phishing detection AI. Analyze this screenshot for phishing threats.
          
Respond ONLY with valid JSON in this exact format:
{
  "isPhishing": true/false,
  "confidence": 0-100,
  "brand": "brand name being impersonated or null",
  "detectedUrl": "any URL visible in screenshot or null",
  "reasons": ["reason1", "reason2"],
  "explanation": "one sentence plain english explanation"
}`
        }
      ];
    } else {
      content = [
        {
          type: 'text',
          text: `You are NekoShield, a phishing detection AI. Analyze this URL for phishing threats: ${url}

You are NekoShield, an aggressive phishing detection AI. Analyze this URL for phishing threats: ${url}

Check for:
1. Brand impersonation - does the URL contain brand names like PayPal, Amazon, Coinbase, Chase, Apple, Microsoft, Netflix, Bank of America, Mercado Libre, Binance while NOT being the official domain
2. Suspicious patterns - words like: secure, verify, login, account, update, confirm, alert, suspend, cancel combined with brand names in the domain
3. Typosquatting - paypaI.com (capital I instead of l), amaz0n.com, g00gle.com
4. Suspicious TLDs for financial sites - .net .info .xyz .online .site instead of .com
5. Subdomain tricks - paypal.com.fake-site.net (real domain is fake-site.net NOT paypal.com)
6. Urgency language in URL - words like: urgent, suspend, cancel, restore, confirm

Be AGGRESSIVE in detection. If the URL has ANY combination of a brand name + suspicious pattern, mark it as phishing with high confidence. When in doubt, flag it.

Respond ONLY with valid JSON in this exact format:
{
  "isPhishing": true/false,
  "confidence": 0-100,
  "brand": "brand name being impersonated or null",
  "reasons": ["reason1", "reason2"],
  "explanation": "one sentence plain english explanation"
}

Respond ONLY with valid JSON in this exact format:
{
  "isPhishing": true/false,
  "confidence": 0-100,
  "brand": "brand name being impersonated or null",
  "reasons": ["reason1", "reason2"],
  "explanation": "one sentence plain english explanation"
}`
        }
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
          const aiResult = JSON.parse(text);

          const signals = [];
          let score = 0;

          if (aiResult.brand) {
            signals.push({ type: 'danger', label: 'Brand Impersonation', value: `Imitating ${aiResult.brand} (${aiResult.confidence}% confidence)` });
            score += Math.floor(aiResult.confidence * 0.4);
          }

          if (aiResult.reasons && aiResult.reasons.length > 0) {
            aiResult.reasons.forEach(reason => {
              signals.push({ type: aiResult.isPhishing ? 'warning' : 'safe', label: 'AI Detection', value: reason });
            });
          }

          if (!aiResult.isPhishing) {
            signals.push({ type: 'safe', label: 'AI Analysis', value: 'No phishing patterns detected' });
          }

          resolve({
            signals,
            score: aiResult.isPhishing ? Math.max(score, 30) : 0,
            brand: aiResult.brand,
            explanation: aiResult.explanation,
            detectedUrl: aiResult.detectedUrl
          });
        } catch {
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
app.listen(PORT, () => console.log(`NekoShield API running on port ${PORT} 🛡️`));
