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

// WhatsApp Bot endpoint
app.use(express.urlencoded({ extended: false }));

app.post('/whatsapp', async function(req, res) {
  var TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
  var TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
  var TWILIO_WHATSAPP_NUMBER = process.env.TWILIO_WHATSAPP_NUMBER;

  var incomingMsg = req.body.Body || '';
  var fromNumber = req.body.From || '';
  var numMedia = parseInt(req.body.NumMedia || '0');

  console.log('WhatsApp message from: ' + fromNumber);
  console.log('Message: ' + incomingMsg);
  console.log('Media count: ' + numMedia);

  var replyText = '';

  try {
    // Check if user sent an image
    if (numMedia > 0) {
      var mediaUrl = req.body.MediaUrl0;
      var mediaType = req.body.MediaContentType0 || 'image/jpeg';

      // Download image from Twilio
      var imageBase64 = await downloadImageAsBase64(mediaUrl, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

      if (imageBase64) {
        var analysis = await analyzeWithAI(null, imageBase64, mediaType);
        replyText = formatWhatsAppReply(analysis, null);
      } else {
        replyText = '⚠️ Could not process the image. Please try again.';
      }

    } else if (incomingMsg.trim()) {
      var msg = incomingMsg.trim();

      // Check if it looks like a URL
      if (msg.startsWith('http://') || msg.startsWith('https://') || msg.includes('.com') || msg.includes('.net') || msg.includes('.org')) {
        var url = msg;
        if (!url.startsWith('http')) url = 'https://' + url;

        var checks = await Promise.allSettled([
          checkGoogleSafeBrowsing(url),
          checkWhois(url),
          analyzeWithAI(url, null)
        ]);

        var combinedResult = { score: 0, signals: [], brand: null, explanation: null, verdict: 'safe' };
        checks.forEach(function(check) {
          if (check.status === 'fulfilled') {
            check.value.signals.forEach(function(s) { combinedResult.signals.push(s); });
            combinedResult.score += check.value.score || 0;
            if (check.value.brand) combinedResult.brand = check.value.brand;
            if (check.value.explanation) combinedResult.explanation = check.value.explanation;
          }
        });

        combinedResult.score = Math.min(100, combinedResult.score);
        if (combinedResult.score >= 70) combinedResult.verdict = 'dangerous';
        else if (combinedResult.score >= 40) combinedResult.verdict = 'suspicious';

        replyText = formatWhatsAppReply(combinedResult, url);

      } else if (msg.toLowerCase() === 'help' || msg.toLowerCase() === 'hola' || msg.toLowerCase() === 'hi' || msg.toLowerCase() === 'hello') {
        replyText = '🛡️ *NekoShield* — Phishing Detection\n\nSend me:\n• A suspicious *link* to analyze it\n• A *screenshot* of a suspicious message\n\nI will tell you if it\'s safe or dangerous! 🐱';
      } else {
        replyText = '🛡️ *NekoShield* here!\n\nSend me a suspicious *link* or a *screenshot* of a message and I\'ll analyze it for you.\n\nExample: https://suspicious-link.com';
      }
    } else {
      replyText = '🛡️ *NekoShield* here! Send me a link or screenshot to analyze. Type *help* for more info.';
    }

  } catch (error) {
    console.error('WhatsApp handler error:', error);
    replyText = '⚠️ Something went wrong. Please try again in a moment.';
  }

  // Send reply via Twilio
  await sendWhatsAppReply(fromNumber, replyText, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_NUMBER);
  res.status(200).send('OK');
});

function formatWhatsAppReply(analysis, url) {
  var verdict = analysis.verdict || 'safe';
  var score = Math.min(100, analysis.score || 0);
  var reply = '';

  if (verdict === 'dangerous') {
    reply = '🚨 *HIGH RISK — Do NOT proceed*\n';
    reply += 'Threat Level: ' + score + '%\n\n';
  } else if (verdict === 'suspicious') {
    reply = '⚠️ *SUSPICIOUS — Proceed with caution*\n';
    reply += 'Threat Level: ' + score + '%\n\n';
  } else {
    reply = '✅ *SECURE — No threats detected*\n\n';
  }

  if (analysis.brand) {
    reply += '🎭 Impersonating: *' + analysis.brand + '*\n';
  }

  if (analysis.explanation) {
    reply += '📋 ' + analysis.explanation + '\n';
  }

  reply += '\n_Analyzed by NekoShield • nekoshield.com_';
  return reply;
}

function downloadImageAsBase64(mediaUrl, accountSid, authToken) {
  return new Promise(function(resolve) {
    var auth = Buffer.from(accountSid + ':' + authToken).toString('base64');
    var urlObj = new URL(mediaUrl);
    var options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: { 'Authorization': 'Basic ' + auth }
    };
    var req = https.request(options, function(response) {
      var chunks = [];
      response.on('data', function(chunk) { chunks.push(chunk); });
      response.on('end', function() {
        var buffer = Buffer.concat(chunks);
        resolve(buffer.toString('base64'));
      });
    });
    req.on('error', function() { resolve(null); });
    req.end();
  });
}

function sendWhatsAppReply(to, body, accountSid, authToken, fromNumber) {
  return new Promise(function(resolve) {
    if (!accountSid || !authToken || !fromNumber) {
      console.log('Twilio credentials missing');
      resolve();
      return;
    }
    var postData = 'To=' + encodeURIComponent(to) + '&From=' + encodeURIComponent('whatsapp:' + fromNumber) + '&Body=' + encodeURIComponent(body);
    var auth = Buffer.from(accountSid + ':' + authToken).toString('base64');
    var options = {
      hostname: 'api.twilio.com',
      path: '/2010-04-01/Accounts/' + accountSid + '/Messages.json',
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + auth,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData)
      }
    };
    var req = https.request(options, function(response) {
      var data = '';
      response.on('data', function(chunk) { data += chunk; });
      response.on('end', function() {
        console.log('Twilio response:', data);
        resolve();
      });
    });
    req.on('error', function(e) {
      console.error('Twilio error:', e);
      resolve();
    });
    req.write(postData);
    req.end();
  });
}

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('NekoShield API running on port ' + PORT);
  console.log('GOOGLE_API_KEY present: ' + !!GOOGLE_API_KEY);
  console.log('ANTHROPIC_API_KEY present: ' + !!ANTHROPIC_API_KEY);
});
