#!/usr/bin/env node
/**
 * ============================================================================
 * AI Recommender - Security Vulnerability Analysis with LLaMA via Ollama
 * ============================================================================
 * Ce script lit les prompts générés par le parser et génère des rapports
 * HTML à partir des réponses du modèle LLaMA via Ollama.
 *
 * Prérequis :
 * - Ollama installé et en cours d'exécution
 * - Modèle LLaMA téléchargé : ollama pull llama3.2
 * - Node.js >= 18
 *
 * Usage:
 *   node ai_recommender.js <input_dir> <output_dir>
 */

const fs = require('fs');
const path = require('path');
const http = require('http');

// ============================================================================
// CONFIGURATION
// ============================================================================
const PROMPTS_DIR = process.argv[2] 
  ? path.join(process.argv[2], 'prompts')
  : './parsed-security-reports/prompts';

const OUTPUT_DIR = process.argv[3] 
  ? process.argv[3]
  : './ai-reports';

const OLLAMA_HOST = process.env.OLLAMA_HOST || 'localhost';
const OLLAMA_PORT = process.env.OLLAMA_PORT || '11434';
const LLM_MODEL = process.env.LLM_MODEL || 'llama3.2';

console.log('📋 Configuration:');
console.log(`   - Prompts directory: ${PROMPTS_DIR}`);
console.log(`   - Output directory: ${OUTPUT_DIR}`);
console.log(`   - Ollama: ${OLLAMA_HOST}:${OLLAMA_PORT}`);
console.log(`   - Model: ${LLM_MODEL}\n`);

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

function writeHTMLReport(filePath, content, metadata = {}) {
  const html = `
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${path.basename(filePath)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      padding: 40px 20px;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      background: white;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      padding: 40px;
    }
    h1 { 
      color: #1a1a1a;
      border-bottom: 4px solid #667eea;
      padding-bottom: 15px;
      margin-bottom: 30px;
      font-size: 2.5em;
    }
    h2 { 
      color: #667eea;
      margin-top: 40px;
      margin-bottom: 15px;
      font-size: 1.8em;
    }
    h3 { 
      color: #424242;
      margin-top: 25px;
      margin-bottom: 10px;
    }
    p { 
      line-height: 1.8;
      margin-bottom: 15px;
      color: #333;
    }
    pre { 
      background: #f5f5f5;
      padding: 15px;
      border-radius: 8px;
      overflow-x: auto;
      border-left: 4px solid #667eea;
      margin: 15px 0;
      font-size: 0.9em;
    }
    code { 
      background: #e3f2fd;
      padding: 2px 8px;
      border-radius: 4px;
      font-family: 'Courier New', monospace;
      font-size: 0.9em;
    }
    ul, ol {
      margin: 15px 0 15px 30px;
      line-height: 1.8;
    }
    li {
      margin-bottom: 8px;
    }
    .severity-critical { 
      color: #d32f2f;
      font-weight: bold;
      background: #ffebee;
      padding: 4px 8px;
      border-radius: 4px;
    }
    .severity-high { 
      color: #f57c00;
      font-weight: bold;
      background: #fff3e0;
      padding: 4px 8px;
      border-radius: 4px;
    }
    .severity-medium { 
      color: #fbc02d;
      font-weight: bold;
      background: #fffde7;
      padding: 4px 8px;
      border-radius: 4px;
    }
    .severity-low { 
      color: #388e3c;
      font-weight: bold;
      background: #e8f5e9;
      padding: 4px 8px;
      border-radius: 4px;
    }
    .metadata {
      background: #f8f9fa;
      padding: 20px;
      border-radius: 8px;
      margin: 20px 0;
      border-left: 4px solid #28a745;
    }
    .metadata p {
      margin: 5px 0;
      color: #555;
      font-size: 0.95em;
    }
    .ai-analysis {
      white-space: pre-wrap;
      word-wrap: break-word;
    }
    footer { 
      margin-top: 60px;
      padding-top: 20px;
      border-top: 2px solid #eee;
      font-size: 0.9em;
      color: #777;
      text-align: center;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
    }
    th, td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #ddd;
    }
    th {
      background: #667eea;
      color: white;
      font-weight: 600;
    }
    tr:hover {
      background: #f5f5f5;
    }
  </style>
</head>
<body>
  <div class="container">
    ${metadata.model ? `
    <div class="metadata">
      <p>🤖 <strong>Modèle IA :</strong> ${metadata.model}</p>
      <p>⏱️ <strong>Généré le :</strong> ${metadata.timestamp}</p>
      <p>⚡ <strong>Temps de traitement :</strong> ${metadata.duration || 'N/A'}</p>
    </div>
    ` : ''}
    ${content}
    <footer>
      <hr>
      <p>Rapport généré par <b>AI Recommender</b> avec LLaMA via Ollama</p>
    </footer>
  </div>
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
// INTERACTION AVEC OLLAMA
// ============================================================================
function queryOllama(prompt) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({
      model: LLM_MODEL,
      prompt: prompt,
      stream: false,
      options: { 
        temperature: 0.7,
        top_p: 0.9,
        num_predict: 4096
      }
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
      timeout: 300000 // 5 minutes
    };

    const req = http.request(options, res => {
      let data = '';
      res.on('data', chunk => (data += chunk));
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          if (response.error) {
            reject(new Error(response.error));
            return;
          }
          resolve(response.response || '');
        } catch (e) {
          reject(new Error('Erreur parsing réponse Ollama: ' + e.message));
        }
      });
    });

    req.on('error', err => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Timeout Ollama (> 5 minutes)'));
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
          const models = response.models || [];
          const hasModel = models.some(m => m.name.includes(LLM_MODEL.split(':')[0]));
          resolve({ 
            available: true, 
            hasModel,
            models: models.map(m => m.name)
          });
        } catch (e) {
          resolve({ available: true, hasModel: false, models: [] });
        }
      });
    });

    req.on('error', () => resolve({ available: false, hasModel: false, models: [] }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ available: false, hasModel: false, models: [] });
    });

    req.end();
  });
}

// ============================================================================
// FORMATAGE MARKDOWN → HTML
// ============================================================================
function simpleMarkdownToHTML(text) {
  return text
    // Titres
    .replace(/^### (.*?)$/gm, '<h3>$1</h3>')
    .replace(/^## (.*?)$/gm, '<h2>$1</h2>')
    .replace(/^# (.*?)$/gm, '<h1>$1</h1>')
    // Gras et italique
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    // Code inline
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    // Blocs de code
    .replace(/```[\s\S]*?```/g, match => {
      const code = match.replace(/```\w*\n?/g, '');
      return `<pre><code>${code}</code></pre>`;
    })
    // Listes
    .replace(/^\* (.*?)$/gm, '<li>$1</li>')
    .replace(/^- (.*?)$/gm, '<li>$1</li>')
    .replace(/^\d+\. (.*?)$/gm, '<li>$1</li>')
    // Paragraphes
    .replace(/\n\n/g, '</p><p>')
    // Sauts de ligne
    .replace(/\n/g, '<br>');
}

// ============================================================================
// MAIN
// ============================================================================
(async () => {
  const startTime = Date.now();
  console.log('\n🚀 Démarrage du AI Recommender avec LLaMA/Ollama...\n');
  
  // Créer le dossier de sortie
  ensureDirectoryExists(OUTPUT_DIR);

  // Vérifier que le dossier des prompts existe
  if (!fs.existsSync(PROMPTS_DIR)) {
    console.error(`❌ Erreur : Le dossier de prompts n'existe pas : ${PROMPTS_DIR}`);
    
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
    console.error('❌ Ollama n\'est pas accessible !');
    console.log('💡 Assurez-vous que Ollama est démarré : ollama serve');
    console.log('   Installation : https://ollama.ai\n');
    
    const errorReport = {
      status: 'error',
      message: 'Ollama not available',
      host: `${OLLAMA_HOST}:${OLLAMA_PORT}`,
      timestamp: new Date().toISOString()
    };
    
    writeJSONSummary(path.join(OUTPUT_DIR, 'error.json'), errorReport);
    process.exit(1);
  }

  if (!ollamaStatus.hasModel) {
    console.error(`❌ Le modèle ${LLM_MODEL} n'est pas installé !`);
    console.log(`💡 Installez-le avec : ollama pull ${LLM_MODEL}`);
    console.log(`   Modèles disponibles : ${ollamaStatus.models.join(', ') || 'aucun'}\n`);
    
    const errorReport = {
      status: 'error',
      message: `Model ${LLM_MODEL} not found`,
      available_models: ollamaStatus.models,
      timestamp: new Date().toISOString()
    };
    
    writeJSONSummary(path.join(OUTPUT_DIR, 'error.json'), errorReport);
    process.exit(1);
  }

  console.log(`✅ Ollama est disponible avec le modèle ${LLM_MODEL} !\n`);

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
    model: LLM_MODEL,
    timestamp: new Date().toISOString(),
    total_duration: 0
  };

  // Traiter chaque prompt
  for (const file of promptFiles) {
    const type = path.basename(file, path.extname(file)).toLowerCase();
    console.log(`\n${'='.repeat(60)}`);
    console.log(`🧠 Traitement du prompt : ${file}`);
    console.log('='.repeat(60));
    
    const promptPath = path.join(PROMPTS_DIR, file);
    const prompt = readPrompt(promptPath);
    
    if (!prompt) {
      summary.failed++;
      continue;
    }

    try {
      const promptStart = Date.now();
      console.log('   ⏳ Envoi à LLaMA...');
      
      const llmResponse = await queryOllama(prompt);
      const duration = ((Date.now() - promptStart) / 1000).toFixed(2);
      
      console.log(`   ✅ Réponse reçue (${duration}s)`);
      console.log('   📝 Génération du rapport HTML...');
      
      // Convertir le markdown en HTML si nécessaire
      const formattedContent = simpleMarkdownToHTML(llmResponse);
      
      const htmlContent = `
        <h1>🔒 ${type.toUpperCase()} Security Report</h1>
        <div class="ai-analysis">
          <p>${formattedContent}</p>
        </div>
      `;
      
      const htmlPath = path.join(OUTPUT_DIR, `${type}_report.html`);
      writeHTMLReport(htmlPath, htmlContent, {
        model: LLM_MODEL,
        timestamp: new Date().toLocaleString('fr-FR'),
        duration: `${duration}s`
      });
      
      summary.processed++;
      summary.total_duration += parseFloat(duration);
      summary.reports.push({
        type,
        file,
        output: path.basename(htmlPath),
        duration_seconds: parseFloat(duration),
        success: true
      });
      
    } catch (error) {
      console.error(`   ❌ Erreur : ${error.message}`);
      summary.failed++;
      summary.reports.push({
        type,
        file,
        error: error.message,
        success: false
      });
    }
  }

  // Générer le résumé JSON
  summary.total_duration = summary.total_duration.toFixed(2);
  writeJSONSummary(path.join(OUTPUT_DIR, 'summary.json'), summary);

  // Rapport final
  const totalTime = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log('\n' + '='.repeat(60));
  console.log('✨ Traitement terminé !');
  console.log('='.repeat(60));
  console.log(`   ✅ Rapports générés : ${summary.processed}`);
  console.log(`   ❌ Échecs : ${summary.failed}`);
  console.log(`   ⏱️  Temps total : ${totalTime}s`);
  console.log(`   📁 Dossier de sortie : ${OUTPUT_DIR}`);
  console.log('='.repeat(60) + '\n');
  
  process.exit(summary.failed > 0 ? 1 : 0);
})();
