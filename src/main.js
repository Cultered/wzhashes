/**
 * Bruteforce Vanity Key Generator Application
 * Main application logic
 */

import { initCrypto, Ed25519, EcKey, Base64, bytesToHex } from './crypto.js';

// DOM Elements
const elements = {
    wasmStatus: document.getElementById('wasmStatus'),
    regexPattern: document.getElementById('regexPattern'),
    maxAttempts: document.getElementById('maxAttempts'),
    startBtn: document.getElementById('startBtn'),
    stopBtn: document.getElementById('stopBtn'),
    statsCard: document.getElementById('statsCard'),
    attempts: document.getElementById('attempts'),
    rate: document.getElementById('rate'),
    elapsed: document.getElementById('elapsed'),
    status: document.getElementById('status'),
    currentHash: document.getElementById('currentHash'),
    progressBar: document.getElementById('progressBar'),
    progressContainer: document.getElementById('progressContainer'),
    resultCard: document.getElementById('resultCard'),
    resultHash: document.getElementById('resultHash'),
    resultPublicKey: document.getElementById('resultPublicKey'),
    resultPrivateKey: document.getElementById('resultPrivateKey'),
    resultPrivateKeyB64: document.getElementById('resultPrivateKeyB64'),
    logContainer: document.getElementById('logContainer')
};

// Application State
let state = {
    running: false,
    attempts: 0,
    startTime: null,
    pattern: null,
    maxAttempts: null,
    worker: null
};

// Logging
function log(message, type = 'info') {
    const entry = document.createElement('div');
    entry.className = `log-entry log-${type}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    elements.logContainer.appendChild(entry);
    elements.logContainer.scrollTop = elements.logContainer.scrollHeight;
}

function clearLog() {
    elements.logContainer.innerHTML = '';
}

// Format numbers with commas
function formatNumber(num) {
    return num.toLocaleString();
}

// Update statistics display
function updateStats() {
    elements.attempts.textContent = formatNumber(state.attempts);
    
    if (state.startTime) {
        const elapsed = (Date.now() - state.startTime) / 1000;
        elements.elapsed.textContent = elapsed.toFixed(1) + 's';
        
        const rate = state.attempts / elapsed;
        elements.rate.textContent = formatNumber(Math.round(rate));
    }
    
    if (state.maxAttempts) {
        const progress = (state.attempts / state.maxAttempts) * 100;
        elements.progressBar.style.width = Math.min(progress, 100) + '%';
    }
}

// Show result
function showResult(result) {
    elements.resultCard.classList.remove('hidden');
    elements.resultHash.textContent = result.hash;
    elements.resultPublicKey.textContent = result.publicKeyHex;
    elements.resultPrivateKey.textContent = result.privateKeyHex;
    elements.resultPrivateKeyB64.textContent = result.privateKeyB64;
}

// Hide result
function hideResult() {
    elements.resultCard.classList.add('hidden');
}

// Start bruteforce
function startBruteforce() {
    const regexInput = elements.regexPattern.value.trim();
    if (!regexInput) {
        log('Please enter a regex pattern', 'error');
        return;
    }
    
    // Validate regex
    try {
        state.pattern = new RegExp(regexInput);
    } catch (e) {
        log(`Invalid regex pattern: ${e.message}`, 'error');
        return;
    }
    
    const maxAttemptsInput = elements.maxAttempts.value.trim();
    state.maxAttempts = maxAttemptsInput ? parseInt(maxAttemptsInput) : null;
    
    // Reset state
    state.running = true;
    state.attempts = 0;
    state.startTime = Date.now();
    
    // Update UI
    elements.startBtn.classList.add('hidden');
    elements.stopBtn.classList.remove('hidden');
    elements.status.textContent = 'Running';
    elements.statsCard.classList.add('running');
    elements.progressBar.style.width = '0%';
    hideResult();
    
    if (state.maxAttempts) {
        elements.progressContainer.style.display = 'block';
    } else {
        elements.progressContainer.style.display = 'none';
    }
    
    clearLog();
    log(`Starting bruteforce with pattern: ${regexInput}`);
    log(`Using libsodium Ed25519 key generation`);
    log('Press Stop to cancel\n');
    
    // Start the bruteforce loop
    runBruteforceLoop();
}

// Stop bruteforce
function stopBruteforce(reason = 'User stopped') {
    state.running = false;
    
    elements.startBtn.classList.remove('hidden');
    elements.stopBtn.classList.add('hidden');
    elements.status.textContent = 'Stopped';
    elements.statsCard.classList.remove('running');
    
    const elapsed = ((Date.now() - state.startTime) / 1000).toFixed(2);
    log(`\n${reason} after ${formatNumber(state.attempts)} attempts in ${elapsed}s`, 'warning');
}

// Main bruteforce loop (using setTimeout for non-blocking)
function runBruteforceLoop() {
    const BATCH_SIZE = 100; // Keys per frame
    const LOG_INTERVAL = 100000; // Log every N attempts
    
    let lastLoggedAttempts = 0;
    
    function processBatch() {
        if (!state.running) return;
        
        for (let i = 0; i < BATCH_SIZE; i++) {
            if (!state.running) return;
            
            // Check max attempts
            if (state.maxAttempts && state.attempts >= state.maxAttempts) {
                stopBruteforce('Max attempts reached');
                log('No match found', 'warning');
                return;
            }
            
            // Generate Ed25519 keypair
            const { publicKey, privateKey } = Ed25519.generateKeypair();
            
            // Create EcKey and get hash
            const ecKey = new EcKey(publicKey, privateKey);
            const hashStr = ecKey.publicHashString();
            
            state.attempts++;
            
            // Log progress periodically
            if (state.attempts - lastLoggedAttempts >= LOG_INTERVAL) {
                lastLoggedAttempts = state.attempts;
                const elapsed = (Date.now() - state.startTime) / 1000;
                const rate = Math.round(state.attempts / elapsed);
                log(`Attempts: ${formatNumber(state.attempts)} | Rate: ${formatNumber(rate)}/s | Current hash: ${hashStr.substring(0, 16)}...`);
            }
            
            // Update current hash display
            if (state.attempts % 1000 === 0) {
                elements.currentHash.textContent = `Current hash: ${hashStr.substring(0, 32)}...`;
                updateStats();
            }
            
            // Check if hash matches pattern
            if (state.pattern.test(hashStr)) {
                const elapsed = ((Date.now() - state.startTime) / 1000).toFixed(2);
                
                state.running = false;
                elements.startBtn.classList.remove('hidden');
                elements.stopBtn.classList.add('hidden');
                elements.status.textContent = 'Found!';
                elements.statsCard.classList.remove('running');
                
                log(`\n✓ MATCH FOUND after ${formatNumber(state.attempts)} attempts in ${elapsed}s!`, 'success');
                log(`Private key: ${bytesToHex(privateKey)}`, 'success');
                log(`Public key:  ${bytesToHex(publicKey)}`, 'success');
                log(`Hash:        ${hashStr}`, 'success');
                log(`Private key (base64): ${Base64.encode(privateKey)}`, 'success');
                
                showResult({
                    hash: hashStr,
                    publicKeyHex: bytesToHex(publicKey),
                    privateKeyHex: bytesToHex(privateKey),
                    privateKeyB64: Base64.encode(privateKey)
                });
                
                updateStats();
                return;
            }
        }
        
        // Continue with next batch
        if (state.running) {
            setTimeout(processBatch, 0);
        }
    }
    
    processBatch();
}

// Initialize
async function init() {
    try {
        // Wait for libsodium to be ready
        await initCrypto();
        
        // Mark crypto as ready
        elements.wasmStatus.className = 'wasm-status ready';
        elements.wasmStatus.textContent = '✓ libsodium-wrappers loaded (Ed25519 + SHA256)';
        
        // Enable start button
        elements.startBtn.disabled = false;
        
        log('libsodium cryptographic library initialized', 'success');
        log('Using Ed25519 key generation with SHA256 hashing');
        log('Enter a regex pattern and click Start to begin');
    } catch (e) {
        elements.wasmStatus.className = 'wasm-status error';
        elements.wasmStatus.textContent = '✗ Failed to load cryptographic modules: ' + e.message;
        log('Failed to initialize crypto: ' + e.message, 'error');
    }
    
    // Event listeners
    elements.startBtn.addEventListener('click', startBruteforce);
    elements.stopBtn.addEventListener('click', () => stopBruteforce('User stopped'));
    
    // Allow Enter key to start
    elements.regexPattern.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !state.running) {
            startBruteforce();
        }
    });
    
    elements.maxAttempts.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !state.running) {
            startBruteforce();
        }
    });
}

// Start the app
init();
