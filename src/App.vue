<template>
  <div class="palaco-container">
    <header class="palaco-header">
      <div class="brand">
        <h1>PALACO</h1>
        <span class="subtitle">HOOFDKANTOOR // VERIFICATIE CONTRACT v1.0 (DRAFT)</span>
      </div>
      <div class="system-status">
        <span class="status-dot" :class="globalStatusClass"></span>
        {{ globalStatusText }}
      </div>
    </header>

    <main class="modules-grid">
      <div v-for="module in modules" :key="module.id" class="module-card" :class="module.status">
        
        <div class="card-header">
          <div class="icon-box" :style="{ color: module.color }">
            <component :is="module.icon" :size="24" />
          </div>
          <div class="status-badge" :class="module.status">
            {{ getStatusLabel(module.status) }}
          </div>
        </div>

        <h2 :style="{ color: module.color }">{{ module.name }}</h2>
        <p class="description">{{ module.description }}</p>

        <!-- Configuratie -->
        <div class="config-section">
          <label>Vertrouwde Origin (HTTPS)</label>
          <div class="input-group">
            <input 
              type="url" 
              v-model="module.inputUrl" 
              placeholder="https://bijv.localhost:5174" 
              @input="handleInput(module)"
              :disabled="module.isVerifying"
              :class="{ error: module.error }"
            />
            <button @click="saveAndVerify(module)" :disabled="!module.isValid || module.isVerifying">
              {{ module.isVerifying ? 'Controleren...' : 'Opslaan & Verifiëren' }}
            </button>
          </div>
          
          <div v-if="module.error" class="error-msg">{{ module.error }}</div>
          
          <div v-if="module.lastCheck" class="check-details">
            <small>Laatste check: {{ new Date(module.lastCheck.time).toLocaleTimeString() }}</small>
            <span v-if="module.lastCheck.result === 'success'" class="success-detail">
              ID Bevestigd: {{ module.lastCheck.receivedId }}
            </span>
            <span v-else-if="module.lastCheck.result === 'fail'" class="fail-detail">
              Fout: {{ module.lastCheck.reason }}
            </span>
          </div>
        </div>

        <button 
          class="launch-btn" 
          :disabled="module.status !== 'verified'"
          @click="openModule(module)"
        >
          {{ module.status === 'verified' ? 'Open Module' : 'Wacht op verificatie' }}
        </button>
      </div>
    </main>

    <footer class="palaco-footer">
      <p>⚠️ Status "Modulemetadata bevestigd" betekent alleen: de goedgekeurde origin leverde de verwachte JSON.</p>
      <p>Dit impliceert geen authenticatie, autorisatie of gegarandeerde veiligheid van de inhoud.</p>
    </footer>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue';
import { Lock, Users, Globe } from 'lucide-vue-next';

// CONFIGURATIE: Vertrouwde Origins
// Alleen URLs die hier staan (of exact matchen met input) worden gecontroleerd.
const TRUSTED_ORIGINS = {
  'aether': ['https://localhost:5174', 'https://aether.hoofdkantoor.info'],
  'bastion': ['https://localhost:5175', 'https://bastion.hoofdkantoor.info'],
  '5criptie': ['https://localhost:5176', 'https://5criptie.hoofdkantoor.info']
};

const modules = ref([
  {
    id: 'aether',
    name: 'AETHER',
    description: 'Cryptografische versleutelingsmachine.',
    icon: Lock,
    color: '#00ff9d',
    expectedId: 'aether',
    inputUrl: '',
    savedUrl: null,
    status: 'unconfigured',
    isValid: false,
    error: '',
    isVerifying: false,
    lastCheck: null,
    abortController: null
  },
  {
    id: 'bastion',
    name: 'BASTION',
    description: 'Commandocentrum & teamcollaboratie.',
    icon: Users,
    color: '#3b82f6',
    expectedId: 'bastion',
    inputUrl: '',
    savedUrl: null,
    status: 'unconfigured',
    isValid: false,
    error: '',
    isVerifying: false,
    lastCheck: null,
    abortController: null
  },
  {
    id: '5criptie',
    name: '5CRIPTIE',
    description: 'Netwerkmonitoring & code-integriteit.',
    icon: Globe,
    color: '#bd00ff',
    expectedId: '5criptie',
    inputUrl: '',
    savedUrl: null,
    status: 'unconfigured',
    isValid: false,
    error: '',
    isVerifying: false,
    lastCheck: null,
    abortController: null
  }
]);

const globalStatusClass = computed(() => {
  const count = modules.value.filter(m => m.status === 'verified').length;
  if (count === 3) return 'ok';
  if (count > 0) return 'warning';
  return 'critical';
});

const globalStatusText = computed(() => {
  const count = modules.value.filter(m => m.status === 'verified').length;
  if (count === 3) return 'Alle modules: Metadata bevestigd';
  if (count > 0) return 'Gedeeltelijke verificatie';
  return 'Geen modules geverifieerd';
});

const getStatusLabel = (status) => {
  const labels = {
    'unconfigured': 'Niet ingesteld',
    'not_approved': 'Bestemming niet goedgekeurd',
    'checking': 'Controleren...',
    'impossible': 'Controle niet mogelijk',
    'failed': 'Verificatie mislukt',
    'verified': 'Modulemetadata bevestigd'
  };
  return labels[status] || status;
};

const handleInput = (module) => {
  module.error = '';
  module.status = 'unconfigured';
  module.lastCheck = null;
  
  if (!module.inputUrl.startsWith('https://')) {
    module.isValid = false;
    return;
  }
  
  try {
    new URL(module.inputUrl);
    module.isValid = true;
  } catch (_) {
    module.isValid = false;
  }
};

const saveAndVerify = async (module) => {
  // Annuleer eventuele lopende check
  if (module.abortController) module.abortController.abort();
  module.abortController = new AbortController();
  
  module.savedUrl = module.inputUrl;
  module.isVerifying = true;
  module.error = '';
  module.lastCheck = null;

  // 1. Check Trusted Origin
  const allowedOrigins = TRUSTED_ORIGINS[module.id] || [];
  if (!allowedOrigins.includes(module.savedUrl)) {
    module.status = 'not_approved';
    module.error = `Deze URL staat niet op de lijst van goedgekeurde origins voor ${module.name}.`;
    module.isVerifying = false;
    return;
  }

  module.status = 'checking';
  const verifyUrl = `${module.savedUrl.replace(/\/$/, '')}\/well-known/palaco-app.json`;

  try {
    const response = await fetch(verifyUrl, {
      method: 'GET',
      redirect: 'error',
      signal: module.abortController.signal,
      headers: { 'Accept': 'application/json' }
    });

    // 2. Check HTTP Status
    if (response.status !== 200) {
      throw new Error(`HTTP Status ${response.status}`);
    }

    // 3. Lees JSON
    const data = await response.json();

    // 4. Validatie Schema
    if (!data.appId || typeof data.appId !== 'string') {
      throw new Error('Ongeldig schema: appId ontbreekt of is geen string');
    }

    // 5. Identiteitsmatch
    if (data.appId !== module.expectedId) {
      throw new Error(`Verkeerde identiteit: verwachtte '${module.expectedId}', kreeg '${data.appId}'`);
    }

    // SUCCES
    module.status = 'verified';
    module.lastCheck = {
      time: Date.now(),
      result: 'success',
      receivedId: data.appId
    };

  } catch (err) {
    if (err.name === 'AbortError') return;

    let reason = err.message;
    let newStatus = 'failed';

    if (err.type === 'opaqueredirect' || reason.includes('redirect')) {
      reason = 'Redirects zijn niet toegestaan';
      newStatus = 'impossible';
    } else if (reason.includes('Failed to fetch') || reason.includes('NetworkError')) {
      reason = 'Netwerkfout, CORS blokkade of server onbereikbaar';
      newStatus = 'impossible';
    } else if (reason.includes('JSON')) {
      reason = 'Geen geldige JSON ontvangen';
      newStatus = 'failed';
    }

    module.status = newStatus;
    module.error = reason;
    module.lastCheck = {
      time: Date.now(),
      result: 'fail',
      reason: reason
    };
  } finally {
    module.isVerifying = false;
  }
};

const openModule = (module) => {
  if (module.status === 'verified' && module.savedUrl) {
    window.open(module.savedUrl, '_blank', 'noopener,noreferrer');
  }
};
</script>

<style scoped>
.palaco-container { min-height: 100vh; background: #050505; color: #e2e8f0; font-family: system-ui, sans-serif; padding: 2rem; display: flex; flex-direction: column; }
.palaco-header { display: flex; justify-content: space-between; border-bottom: 2px solid #333; padding-bottom: 1.5rem; margin-bottom: 2rem; }
.brand h1 { margin: 0; font-size: 2rem; letter-spacing: 2px; text-transform: uppercase; }
.subtitle { display: block; font-size: 0.8rem; color: #64748b; margin-top: 5px; }
.system-status { display: flex; align-items: center; gap: 0.5rem; font-weight: bold; background: #111; padding: 0.5rem 1rem; border-radius: 4px; border: 1px solid #333; }
.status-dot { width: 10px; height: 10px; border-radius: 50%; }
.status-dot.ok { background: #10b981; box-shadow: 0 0 8px #10b981; }
.status-dot.warning { background: #f59e0b; box-shadow: 0 0 8px #f59e0b; }
.status-dot.critical { background: #ef4444; box-shadow: 0 0 8px #ef4444; }

.modules-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 2rem; flex: 1; }
.module-card { background: #0a0a0a; border: 1px solid #333; border-radius: 8px; padding: 1.5rem; display: flex; flex-direction: column; transition: all 0.3s; }
.module-card.verified { border-color: #10b981; box-shadow: 0 0 15px rgba(16, 185, 129, 0.1); }
.module-card.failed { border-color: #ef4444; }
.module-card.impossible { border-color: #f59e0b; }
.module-card.not_approved { border-color: #64748b; }

.card-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem; }
.icon-box { background: rgba(255,255,255,0.05); padding: 8px; border-radius: 6px; }
.status-badge { font-size: 0.65rem; padding: 4px 8px; border-radius: 4px; text-transform: uppercase; font-weight: bold; border: 1px solid transparent; }
.status-badge.verified { background: rgba(16, 185, 129, 0.1); color: #10b981; border-color: #10b981; }
.status-badge.failed { background: rgba(239, 68, 68, 0.1); color: #ef4444; border-color: #ef4444; }
.status-badge.impossible { background: rgba(245, 158, 11, 0.1); color: #f59e0b; border-color: #f59e0b; }
.status-badge.not_approved { background: #333; color: #94a3b8; }
.status-badge.checking { background: #333; color: #fff; animation: pulse 1s infinite; }

h2 { margin: 0 0 0.5rem 0; font-size: 1.5rem; }
.description { color: #94a3b8; font-size: 0.9rem; margin-bottom: 1.5rem; flex-grow: 1; }
.config-section { background: #111; padding: 1rem; border-radius: 6px; margin-bottom: 1.5rem; border: 1px solid #222; }
label { display: block; font-size: 0.7rem; color: #64748b; margin-bottom: 0.5rem; text-transform: uppercase; }
.input-group { display: flex; gap: 0.5rem; }
input { flex: 1; background: #050505; border: 1px solid #333; color: #fff; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 0.85rem; }
input.error { border-color: #ef4444; }
button { background: #333; color: #fff; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 0.8rem; }
button:disabled { opacity: 0.5; cursor: not-allowed; }
button:not(:disabled):hover { background: #555; }
.error-msg { color: #ef4444; font-size: 0.75rem; margin-top: 0.5rem; }
.check-details { margin-top: 0.5rem; font-size: 0.7rem; color: #94a3b8; display: flex; flex-direction: column; gap: 2px; }
.success-detail { color: #10b981; }
.fail-detail { color: #ef4444; }

.launch-btn { width: 100%; padding: 12px; text-transform: uppercase; letter-spacing: 1px; font-weight: bold; }
.launch-btn:disabled { background: #222; color: #555; }
.module-card.verified .launch-btn { background: #10b981; color: #000; }
.module-card.verified .launch-btn:hover { background: #34d399; }

.palaco-footer { margin-top: 3rem; text-align: center; font-size: 0.7rem; color: #475569; border-top: 1px solid #222; padding-top: 1rem; }

@keyframes pulse { 50% { opacity: 0.5; } }
</style>
