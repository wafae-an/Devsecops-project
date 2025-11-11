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
const PROMPTS_DIR = process.argv[2] 
  ? path.join(process.argv[2], 'prompts')
  : (process.env.PROMPTS_DIR || './parsed-security-reports/prompts');

const OUTPUT_DIR = process.argv[3] 
  ? process.argv[3]
  : (process.env.OUTPUT_DIR || './ai-reports');

const OLLAMA_HOST = process.env.OLLAMA_HOST || 'localhost';
const OLLAMA_PORT = process.env.OLLAMA_PORT || '11434';
const LLM_MODEL = process.env.LLM_MODEL || 'llama3.2';

console.log('📋 Configuration:');
console.log(`   - Prompts directory: ${PROMPTS_DIR}`);
console.log(`   - Output directory: ${OUTPUT_DIR}`);
console.log(`   - Ollama: ${OLLAMA_HOST}:${OLLAMA_PORT}`);
console.log(`   - Model: ${LLM_MODEL}`);

// ============================================================================
// OUTILS
// ============================================================================
function ensureDirectoryExists(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`📁 Dossier créé : ${dir}`);
  }
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${path.basename(filePath)}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #fafafa; color: #333; }
    h1 { color: #0d47a1; border-bottom: 3px solid #0d47a1; padding-bottom: 5px; }
    h2 { color: #1976d2; margin-top: 30px; }
    h3 { color: #424242; }
    pre { background: #eee; padding: 10px; border-radius: 6px; overflow-x: auto; }
    code { background: #e3f2fd; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
    .severity-critical { color: #d32f2f; font-weight: bold; }
    .severity-high { color: #f57c00; font-weight: bold; }
    .severity-medium { color: #fbc02d; font-weight: bold; }
    .severity-low { color: #388e3c; font-weight: bold; }
    footer { margin-top: 40px; font-size: 0.85em; color: #777; text-align: center; }
  </style>
</head>
<body>
  ${content}
  <footer>
    <hr>
    <p>Rapport généré par <b>AI Recommender (LLaMA)</b> — ${new Date().toLocaleString('fr-FR')}</p>
  </footer>
</body>
</html>`;
  fs.writeFileSync(filePath, html, 'utf-8');
  console.log(`✅ Rapport généré : ${filePath}`);
}

function writeJSONSummary(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
  console.log(`📄 Résumé JSON créé : ${filePath}`);
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
// VÉRIFICATION DISPONIBILITÉ OLLAMA
// ============================================================================
function checkOllamaAvailability() {
  return new Promise((resolve) => {
    const options = {
      hostname: OLLAMA_HOST,
      port: OLLAMA_PORT,
      path: '/api/tags',
      method: 'GET',
      timeout: 5000
    };

    const req = http.request(options, res => {
      let data = '';
      res.on('data', chunk => (data += chunk));
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          const hasModel = response.models?.some(m => m.name.includes(LLM_MODEL));
          resolve({ available: true, hasModel });
        } catch (e) {
          resolve({ available: true, hasModel: false });
        }
      });
    });

    req.on('error', () => resolve({ available: false, hasModel: false }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ available: false, hasModel: false });
    });

    req.end();
  });
}

// ============================================================================
// MAIN
// ============================================================================
(async () => {
  console.log('\n🚀 Démarrage du AI Recommender (à partir des prompts)...\n');
  
  // Créer le dossier de sortie
  ensureDirectoryExists(OUTPUT_DIR);

  // Vérifier que le dossier des prompts existe
  if (!fs.existsSync(PROMPTS_DIR)) {
    console.error(`❌ Erreur : Le dossier de prompts n'existe pas : ${PROMPTS_DIR}`);
    console.log('📝 Création d\'un rapport d\'erreur...');
    
    const errorReport = {
      status: 'error',
      message: 'Prompts directory not found',
      expected_path: PROMPTS_DIR,
      timestamp: new Date().toISOString()
    };
    
    writeJSONSummary(path.join(OUTPUT_DIR, 'error.json'), errorReport);
    process.exit(1);
  }

  // Vérifier la disponibilité d'Ollama
  console.log('🔍 Vérification de la disponibilité d\'Ollama...');
  const ollamaStatus = await checkOllamaAvailability();
  
  if (!ollamaStatus.available) {
    console.warn('⚠️ Ollama n\'est pas disponible. Les rapports seront générés sans analyse IA.');
    console.log('💡 Pour utiliser l\'IA, installez Ollama : https://ollama.ai\n');
  } else if (!ollamaStatus.hasModel) {
    console.warn(`⚠️ Le modèle ${LLM_MODEL} n'est pas installé.`);
    console.log(`💡 Installez-le avec : ollama pull ${LLM_MODEL}\n`);
  } else {
    console.log('✅ Ollama est disponible et le modèle est prêt !\n');
  }

  // Lire les fichiers de prompts
  const promptFiles = fs.readdirSync(PROMPTS_DIR).filter(f => 
    f.endsWith('.txt') || f.endsWith('.md')
  );
  
  if (promptFiles.length === 0) {
    console.log('⚠️ Aucun prompt trouvé dans', PROMPTS_DIR);
    
    const emptyReport = {
      status: 'no_prompts',
      message: 'No prompt files found',
      searched_in: PROMPTS_DIR,
      timestamp: new Date().toISOString()
    };
    
    writeJSONSummary(path.join(OUTPUT_DIR, 'status.json'), emptyReport);
    process.exit(0);
  }

  console.log(`📂 ${promptFiles.length} prompt(s) trouvé(s)\n`);

  const summary = {
    total_prompts: promptFiles.length,
    processed: 0,
    failed: 0,
    reports: [],
    ollama_available: ollamaStatus.available && ollamaStatus.hasModel,
    timestamp: new Date().toISOString()
  };

  // Traiter chaque prompt
  for (const file of promptFiles) {
    const type = path.basename(file, path.extname(file)).toLowerCase();
    console.log(`🧠 Traitement du prompt : ${file}`);
    
    const promptPath = path.join(PROMPTS_DIR, file);
    const prompt = readPrompt(promptPath);
    
    if (!prompt) {
      summary.failed++;
      continue;
    }

    try {
      let htmlContent;
      
      if (ollamaStatus.available && ollamaStatus.hasModel) {
        // Générer avec l'IA
        const llmResponse = await queryLLM(prompt);
        htmlContent = `
          <h1>🔒 ${type.toUpperCase()} Security Report</h1>
          <div class="ai-analysis">
            ${llmResponse}
          </div>
        `;
      } else {
        // Générer sans l'IA (afficher le prompt seulement)
        htmlContent = `
          <h1>🔒 ${type.toUpperCase()} Security Report</h1>
          <div class="warning" style="background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0;">
            <strong>⚠️ Rapport généré sans analyse IA</strong>
            <p>Ollama n'était pas disponible lors de la génération de ce rapport.</p>
          </div>
          <h2>📋 Prompt d'analyse</h2>
          <pre>${prompt}</pre>
        `;
      }
      
      const htmlPath = path.join(OUTPUT_DIR, `${type}_report.html`);
      writeHTMLReport(htmlPath, htmlContent);
      
      summary.processed++;
      summary.reports.push({
        type,
        file,
        output: path.basename(htmlPath),
        ai_processed: ollamaStatus.available && ollamaStatus.hasModel
      });
      
    } catch (error) {
      console.error(`❌ Erreur sur ${file} :`, error.message);
      summary.failed++;
    }
  }

  // Générer le résumé JSON
  writeJSONSummary(path.join(OUTPUT_DIR, 'summary.json'), summary);

  // Rapport final
  console.log('\n' + '='.repeat(60));
  console.log('✨ Traitement terminé !');
  console.log(`   ✅ Rapports générés : ${summary.processed}`);
  console.log(`   ❌ Échecs : ${summary.failed}`);
  console.log(`   📁 Dossier de sortie : ${OUTPUT_DIR}`);
  console.log('='.repeat(60) + '\n');
})();
