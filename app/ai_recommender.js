#!/usr/bin/env node
/**
 * ============================================================================
 * AI Recommender - Security Vulnerability Analysis with LLaMA (from Prompts)
 * ============================================================================
 * Ce script lit les prompts générés par le parser dans :
 *   ./parsed-security-reports/prompts/
 * et génère des rapports HTML à partir des réponses du modèle LLaMA.
 *
 * Prérequis :
 * - Ollama installé localement (https://ollama.ai)
 * - Modèle LLaMA téléchargé : ollama pull llama3.2
 * - Node.js >= 18
 */

const fs = require('fs');
const path = require('path');
const http = require('http');

// ============================================================================
// CONFIGURATION
// ============================================================================
const PROMPTS_DIR = process.env.PROMPTS_DIR || './parsed-security-reports/prompts';
const OUTPUT_DIR = process.env.OUTPUT_DIR || './output/reports';
const OLLAMA_HOST = process.env.OLLAMA_HOST || 'localhost';
const OLLAMA_PORT = process.env.OLLAMA_PORT || '11434';
const LLM_MODEL = process.env.LLM_MODEL || 'llama3.2';

// ============================================================================
// OUTILS
// ============================================================================
function ensureDirectoryExists(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function readPrompt(filePath) {
  if (!fs.existsSync(filePath)) {
    console.warn(`⚠️ Fichier prompt introuvable : ${filePath}`);
    return null;
  }
  return fs.readFileSync(filePath, 'utf-8');
}

function writeHTMLReport(filePath, content) {
  const html = `
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>${path.basename(filePath)}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #fafafa; color: #333; }
    h1 { color: #0d47a1; border-bottom: 3px solid #0d47a1; padding-bottom: 5px; }
    h2 { color: #1976d2; }
    pre { background: #eee; padding: 10px; border-radius: 6px; overflow-x: auto; }
    footer { margin-top: 40px; font-size: 0.85em; color: #777; text-align: center; }
  </style>
</head>
<body>
  ${content}
  <footer>
    <hr>
    <p>Rapport généré par <b>AI Recommender (LLaMA)</b> — ${new Date().toLocaleString()}</p>
  </footer>
</body>
</html>`;
  fs.writeFileSync(filePath, html, 'utf-8');
  console.log(`✅ Rapport généré : ${filePath}`);
}

// ============================================================================
// INTERACTION AVEC LLaMA (OLLAMA)
// ============================================================================
function queryLLM(prompt) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({
      model: LLM_MODEL,
      prompt: prompt,
      stream: false,
      options: { temperature: 0.7, top_p: 0.9, max_tokens: 4096 }
    });

    const options = {
      hostname: OLLAMA_HOST,
      port: OLLAMA_PORT,
      path: '/api/generate',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      },
      timeout: 120000
    };

    const req = http.request(options, res => {
      let data = '';
      res.on('data', chunk => (data += chunk));
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          resolve(response.response || '');
        } catch (e) {
          reject(new Error('Erreur parsing réponse LLM: ' + e.message));
        }
      });
    });

    req.on('error', err => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Timeout Ollama'));
    });

    req.write(postData);
    req.end();
  });
}

// ============================================================================
// MAIN
// ============================================================================
(async () => {
  console.log('🚀 Démarrage du AI Recommender (à partir des prompts)...');
  ensureDirectoryExists(OUTPUT_DIR);

  const promptFiles = fs.readdirSync(PROMPTS_DIR).filter(f => f.endsWith('.txt') || f.endsWith('.md'));
  if (promptFiles.length === 0) {
    console.log('⚠️ Aucun prompt trouvé dans', PROMPTS_DIR);
    process.exit(0);
  }

  for (const file of promptFiles) {
    const type = path.basename(file, path.extname(file)).toLowerCase();
    console.log(`\n🧠 Traitement du prompt : ${file}`);
    const prompt = readPrompt(path.join(PROMPTS_DIR, file));
    if (!prompt) continue;

    try {
      const llmResponse = await queryLLM(prompt);
      const htmlPath = path.join(OUTPUT_DIR, `${type}_report.html`);
      const htmlContent = `<h1>${type.toUpperCase()} Security Report</h1>\n${llmResponse}`;
      writeHTMLReport(htmlPath, htmlContent);
    } catch (error) {
      console.error(`❌ Erreur sur ${file} :`, error.message);
    }
  }

  console.log('\n✨ Tous les rapports IA ont été générés avec succès !');
})();
