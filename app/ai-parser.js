#!/usr/bin/env node

/**
 * AI Parser - Security Reports Normalizer
 * 
 * Ce script lit les rapports de sécurité (SAST, SCA, DAST),
 * normalise les données et génère des fichiers JSON + prompts
 * pour analyse par IA.
 * 
 * Variables d'environnement requises:
 * - REPORTS_DIR: dossier contenant les rapports
 * - OUTPUT_DIR: dossier de sortie pour les fichiers générés
 */

const fs = require('fs');
const path = require('path');

// ============================================================================
// CONFIGURATION
// ============================================================================

const REPORTS_DIR = process.env.REPORTS_DIR || './reports';
const OUTPUT_DIR = process.env.OUTPUT_DIR || './output';

const SAST_DIR = path.join(REPORTS_DIR, 'sast');
const SCA_DIR = path.join(REPORTS_DIR, 'sca');
const DAST_DIR = path.join(REPORTS_DIR, 'dast');

const JSON_OUTPUT_DIR = path.join(OUTPUT_DIR, 'json');
const PROMPTS_OUTPUT_DIR = path.join(OUTPUT_DIR, 'prompts');

// ============================================================================
// FONCTIONS UTILITAIRES
// ============================================================================

/**
 * Crée un dossier s'il n'existe pas
 */
function ensureDirectoryExists(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

/**
 * Lit tous les fichiers d'un dossier
 */
function readFilesFromDirectory(dir) {
  if (!fs.existsSync(dir)) {
    return [];
  }
  return fs.readdirSync(dir).map(file => ({
    name: file,
    path: path.join(dir, file),
    content: fs.readFileSync(path.join(dir, file), 'utf-8')
  }));
}

/**
 * Normalise la sévérité
 */
function normalizeSeverity(severity) {
  if (!severity) return 'UNKNOWN';
  const s = severity.toString().toUpperCase();
  if (s.includes('CRITICAL') || s.includes('CRIT')) return 'CRITICAL';
  if (s.includes('HIGH')) return 'HIGH';
  if (s.includes('MEDIUM') || s.includes('MED')) return 'MEDIUM';
  if (s.includes('LOW')) return 'LOW';
  if (s.includes('INFO')) return 'INFO';
  return s;
}

// ============================================================================
// PARSERS SAST
// ============================================================================

/**
 * Parse les fichiers SARIF (SAST)
 */
function parseSARIF(content) {
  try {
    const sarif = JSON.parse(content);
    const vulnerabilities = [];

    if (sarif.runs && Array.isArray(sarif.runs)) {
      sarif.runs.forEach(run => {
        if (run.results && Array.isArray(run.results)) {
          run.results.forEach(result => {
            const rule = run.tool?.driver?.rules?.find(r => r.id === result.ruleId) || {};
            const location = result.locations?.[0]?.physicalLocation?.artifactLocation?.uri || 'unknown';

            vulnerabilities.push({
              id: result.ruleId || 'N/A',
              name: rule.name || result.message?.text || 'Unknown vulnerability',
              severity: normalizeSeverity(result.level || rule.defaultConfiguration?.level),
              file: location,
              description: rule.fullDescription?.text || rule.shortDescription?.text || result.message?.text || 'No description',
              recommendation: rule.help?.text || rule.helpUri || 'No recommendation available'
            });
          });
        }
      });
    }

    return vulnerabilities;
  } catch (e) {
    console.warn('⚠️  Erreur lors du parsing SARIF:', e.message);
    return [];
  }
}

/**
 * Parse les fichiers HTML (SAST - basique)
 */
function parseHTML(content) {
  const vulnerabilities = [];
  
  // Extraction basique depuis HTML (à adapter selon le format)
  const cweMatches = content.matchAll(/CWE-(\d+)/gi);
  const severityMatches = content.matchAll(/(CRITICAL|HIGH|MEDIUM|LOW)/gi);
  
  const cwes = Array.from(cweMatches);
  const severities = Array.from(severityMatches);

  for (let i = 0; i < Math.min(cwes.length, severities.length); i++) {
    vulnerabilities.push({
      id: `CWE-${cwes[i][1]}`,
      name: `Vulnerability CWE-${cwes[i][1]}`,
      severity: normalizeSeverity(severities[i][1]),
      file: 'See HTML report',
      description: 'Extracted from HTML report',
      recommendation: 'Refer to HTML report for details'
    });
  }

  return vulnerabilities;
}

/**
 * Parse tous les rapports SAST
 */
function parseSASTReports() {
  const files = readFilesFromDirectory(SAST_DIR);
  let allVulnerabilities = [];

  files.forEach(file => {
    if (file.name.endsWith('.sarif') || file.name.endsWith('.json')) {
      allVulnerabilities = allVulnerabilities.concat(parseSARIF(file.content));
    } else if (file.name.endsWith('.html')) {
      allVulnerabilities = allVulnerabilities.concat(parseHTML(file.content));
    }
  });

  return {
    tool: 'SAST',
    vulnerabilities: allVulnerabilities
  };
}

// ============================================================================
// PARSERS SCA
// ============================================================================

/**
 * Parse les fichiers JSON SCA
 */
function parseSCAJSON(content) {
  try {
    const data = JSON.parse(content);
    const vulnerabilities = [];

    // Format générique SCA
    if (data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
      data.vulnerabilities.forEach(vuln => {
        vulnerabilities.push({
          id: vuln.id || vuln.cve || 'N/A',
          name: vuln.title || vuln.name || 'Unknown vulnerability',
          severity: normalizeSeverity(vuln.severity),
          file: vuln.package || vuln.library || vuln.dependency || 'unknown',
          description: vuln.description || 'No description',
          recommendation: vuln.recommendation || vuln.fix || 'Update to latest version'
        });
      });
    }
    // Format npm audit
    else if (data.vulnerabilities) {
      Object.keys(data.vulnerabilities).forEach(pkg => {
        const vuln = data.vulnerabilities[pkg];
        if (vuln.via && Array.isArray(vuln.via)) {
          vuln.via.forEach(v => {
            if (typeof v === 'object') {
              vulnerabilities.push({
                id: v.cve || v.id || 'N/A',
                name: v.title || 'Dependency vulnerability',
                severity: normalizeSeverity(v.severity),
                file: pkg,
                description: v.url || 'See package for details',
                recommendation: vuln.fixAvailable ? 'Update available' : 'No fix available'
              });
            }
          });
        }
      });
    }

    return vulnerabilities;
  } catch (e) {
    console.warn('⚠️  Erreur lors du parsing SCA JSON:', e.message);
    return [];
  }
}

/**
 * Parse les fichiers TXT SCA
 */
function parseSCATXT(content) {
  const vulnerabilities = [];
  const lines = content.split('\n');
  
  lines.forEach(line => {
    // Extraction basique de CVE depuis texte
    const cveMatch = line.match(/CVE-\d{4}-\d+/i);
    const severityMatch = line.match(/(CRITICAL|HIGH|MEDIUM|LOW)/i);
    
    if (cveMatch) {
      vulnerabilities.push({
        id: cveMatch[0],
        name: `Vulnerability ${cveMatch[0]}`,
        severity: severityMatch ? normalizeSeverity(severityMatch[1]) : 'UNKNOWN',
        file: 'See TXT report',
        description: line.trim(),
        recommendation: 'Update affected package'
      });
    }
  });

  return vulnerabilities;
}

/**
 * Parse tous les rapports SCA
 */
function parseSCAReports() {
  const files = readFilesFromDirectory(SCA_DIR);
  let allVulnerabilities = [];

  files.forEach(file => {
    if (file.name.endsWith('.json')) {
      allVulnerabilities = allVulnerabilities.concat(parseSCAJSON(file.content));
    } else if (file.name.endsWith('.txt')) {
      allVulnerabilities = allVulnerabilities.concat(parseSCATXT(file.content));
    }
  });

  return {
    tool: 'SCA',
    vulnerabilities: allVulnerabilities
  };
}

// ============================================================================
// PARSERS DAST
// ============================================================================

/**
 * Parse les fichiers JSON DAST
 */
function parseDASTJSON(content) {
  try {
    const data = JSON.parse(content);
    const vulnerabilities = [];

    // Format ZAP/OWASP
    if (data.site && Array.isArray(data.site)) {
      data.site.forEach(site => {
        if (site.alerts && Array.isArray(site.alerts)) {
          site.alerts.forEach(alert => {
            vulnerabilities.push({
              id: alert.pluginid || alert.id || 'N/A',
              name: alert.name || alert.alert || 'Unknown vulnerability',
              severity: normalizeSeverity(alert.riskdesc?.split(' ')[0] || alert.risk),
              file: alert.url || site.name || 'unknown',
              description: alert.desc || alert.description || 'No description',
              recommendation: alert.solution || alert.recommendation || 'No recommendation available'
            });
          });
        }
      });
    }
    // Format générique
    else if (data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
      data.vulnerabilities.forEach(vuln => {
        vulnerabilities.push({
          id: vuln.id || 'N/A',
          name: vuln.name || vuln.title || 'Unknown vulnerability',
          severity: normalizeSeverity(vuln.severity),
          file: vuln.url || vuln.endpoint || 'unknown',
          description: vuln.description || 'No description',
          recommendation: vuln.recommendation || vuln.solution || 'No recommendation available'
        });
      });
    }

    return vulnerabilities;
  } catch (e) {
    console.warn('⚠️  Erreur lors du parsing DAST JSON:', e.message);
    return [];
  }
}

/**
 * Parse tous les rapports DAST
 */
function parseDASTReports() {
  const files = readFilesFromDirectory(DAST_DIR);
  let allVulnerabilities = [];

  files.forEach(file => {
    if (file.name.endsWith('.json')) {
      allVulnerabilities = allVulnerabilities.concat(parseDASTJSON(file.content));
    }
  });

  return {
    tool: 'DAST',
    vulnerabilities: allVulnerabilities
  };
}

// ============================================================================
// GÉNÉRATION DES FICHIERS
// ============================================================================

/**
 * Génère les fichiers JSON normalisés
 */
function generateJSONFiles(sastData, scaData, dastData) {
  ensureDirectoryExists(JSON_OUTPUT_DIR);

  fs.writeFileSync(
    path.join(JSON_OUTPUT_DIR, 'normalized_sast.json'),
    JSON.stringify(sastData, null, 2)
  );

  fs.writeFileSync(
    path.join(JSON_OUTPUT_DIR, 'normalized_sca.json'),
    JSON.stringify(scaData, null, 2)
  );

  fs.writeFileSync(
    path.join(JSON_OUTPUT_DIR, 'normalized_dast.json'),
    JSON.stringify(dastData, null, 2)
  );

  console.log('✅ JSON files generated successfully.');
}

/**
 * Génère les fichiers prompts
 */
function generatePromptFiles(sastData, scaData, dastData) {
  ensureDirectoryExists(PROMPTS_OUTPUT_DIR);

  const types = [
    { data: sastData, file: 'prompt_sast.txt', type: 'SAST' },
    { data: scaData, file: 'prompt_sca.txt', type: 'SCA' },
    { data: dastData, file: 'prompt_dast.txt', type: 'DAST' }
  ];

  types.forEach(({ data, file, type }) => {
    const prompt = `Analyse les vulnérabilités suivantes issues du scan ${type}.
Pour chaque vulnérabilité, donne des recommandations techniques précises pour corriger le problème.
Voici les données :

${JSON.stringify(data, null, 2)}`;

    fs.writeFileSync(
      path.join(PROMPTS_OUTPUT_DIR, file),
      prompt
    );
  });

  console.log('✅ Prompt files generated successfully.');
}

// ============================================================================
// MAIN
// ============================================================================

function main() {
  console.log('🚀 AI Parser - Démarrage...\n');

  console.log(`📁 REPORTS_DIR: ${REPORTS_DIR}`);
  console.log(`📁 OUTPUT_DIR: ${OUTPUT_DIR}\n`);

  // Parse les rapports
  console.log('📊 Parsing SAST reports...');
  const sastData = parseSASTReports();
  console.log(`   → ${sastData.vulnerabilities.length} vulnerabilities found\n`);

  console.log('📊 Parsing SCA reports...');
  const scaData = parseSCAReports();
  console.log(`   → ${scaData.vulnerabilities.length} vulnerabilities found\n`);

  console.log('📊 Parsing DAST reports...');
  const dastData = parseDASTReports();
  console.log(`   → ${dastData.vulnerabilities.length} vulnerabilities found\n`);

  // Génère les fichiers de sortie
  console.log('📝 Generating output files...\n');
  generateJSONFiles(sastData, scaData, dastData);
  generatePromptFiles(sastData, scaData, dastData);

  console.log('\n✨ Traitement terminé avec succès!');
}

// Exécution
if (require.main === module) {
  main();
}

module.exports = { parseSASTReports, parseSCAReports, parseDASTReports };
