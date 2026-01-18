let proxyEnabled;

window.addEventListener('load', () => {
  console.log('Page loaded');
  // Prevent disabling proxy on app load or refresh
  // disableProxyOnLoad flag remains false to avoid auto-disable
});

async function disableProxy() {
  try {
    const res = await fetch('/api/proxy/disable', { method: 'POST' });
    if (res.ok) {
      console.log('Proxy disabled');
      updateProxyUI(false);
      // Also stop the proxy process if running (Electron)
      if (proxyProcess) {
        proxyProcess.kill();
        proxyProcess = null;
        proxyActiveProject = null;
        clearProxyState();
        showFeedback('Proxy process stopped.');
      }
    } else {
      console.log('Failed to disable proxy');
    }
  } catch (err) {
    console.log('Error disabling proxy:', err);
  }
}

// Override fetch to log calls to /api/proxy/disable
const originalFetch = window.fetch;
window.fetch = function (...args) {
  const url = args[0] instanceof Request ? args[0].url : args[0];
  if (url.includes('/api/proxy/disable')) {
    console.log('Disable proxy API called:', url);
  }
  return originalFetch.apply(this, args);
};

// Similarly, add logging to XMLHttpRequest if used
const originalXHROpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function (method, url, ...rest) {
  this._method = method;
  this._url = url;
  if (url.includes('/api/proxy/disable')) {
    console.log('Disable proxy API called via XHR:', url);
  }
  return originalXHROpen.apply(this, [method, url, ...rest]);
};

// Check if running in Electron
const isElectron = !!(typeof process !== 'undefined' && process.versions && process.versions.electron);

let path;
let updateCurrentProjectFile
if (isElectron) {
  path = require('path');
  updateCurrentProjectFile = require('./updateCurrentProject.js').updateCurrentProjectFile;

}
else {
  updateCurrentProjectFile = function (projectName, endpoints = null, proxyEnabled = null) {
    fetch('/api/project/update-current', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ projectName, endpoints, proxyEnabled })
    })
  };
}
let ruleDetails;

let selectedEndpointPath = null;

const projectsList = document.getElementById('projectsList');
const folderInput = document.getElementById('folderInput');
const endpointsList = document.getElementById('endpointsList');
const tabButtons = document.querySelectorAll('.tab-btn');
const endpointsTab = document.getElementById('endpointsTab');
const proxyTab = document.getElementById('proxyTab');
const projectsTabBtn = document.querySelector('.tab-btn[data-tab="projects"]');
const tabContents = document.querySelectorAll('.tab-content');
const currentProjectDisplay = document.getElementById('currentProjectDisplay');
const exitEditModeBtn = document.getElementById('exitEditModeBtn');
const addEndpointBtn = document.getElementById('addEndpointBtn');
const newEndpointInput = document.getElementById('newEndpointInput');
const endpointSettingsSection = document.getElementById('endpointSettings');
const feedbackDisplay = document.getElementById('feedback-display');
const detailsPopup = document.createElement('div');
// Add IPS tab button dynamically
const ipsTabBtn = document.createElement('button');
ipsTabBtn.className = 'tab-btn';
ipsTabBtn.dataset.tab = 'ips';
ipsTabBtn.textContent = 'IPS';
ipsTabBtn.style.display = 'none'; // Hidden by default
// Safely append the IPS tab button if the `.tabs` container exists.
// If the script runs before the DOM is ready, wait for DOMContentLoaded.
const _tabsContainer = document.querySelector('.tabs');
if (_tabsContainer) {
  _tabsContainer.appendChild(ipsTabBtn);
} else {
  document.addEventListener('DOMContentLoaded', () => {
    const tabsAfterLoad = document.querySelector('.tabs');
    if (tabsAfterLoad) tabsAfterLoad.appendChild(ipsTabBtn);
  });
}




// --- Regex Validation Function ---
function isValidRegex(pattern) {
  try {
    new RegExp(pattern);
    return true;
  } catch (e) {
    return false;
  }
}

// --- Regex Characters Data ---
const regexCharacters = [
  { char: '.', description: 'Matches any single character (except a newline).', example: 'b.t matches "bat", "bet", "bit"' },
  { char: '[ ]', description: 'Matches any single character within the brackets (e.g., `[abc]` matches "a", "b", or "c").', example: '[aeiou] matches any vowel' },
  { char: '[^ ]', description: 'Matches any character NOT within the brackets.', example: '[^0-9] matches any non-digit' },
  { char: '*', description: 'Matches the preceding character zero or more times.', example: 'bo* matches "b", "bo", "boo"' },
  { char: '+', description: 'Matches the preceding character one or more times.', example: 'bo+ matches "bo", "boo", but not "b"' },
  { char: '?', description: 'Matches the preceding character zero or one time.', example: 'colou?r matches "color" or "colour"' },
  { char: '^', description: 'Matches the beginning of the string.', example: '^Hello matches strings starting with "Hello"' },
  { char: '$', description: 'Matches the end of the string.', example: 'world$ matches strings ending with "world"' },
  { char: '\\d', description: 'Matches any digit (0-9).', example: '\\d{3} matches "123" or "456"' },
  { char: '\\s', description: 'Matches any whitespace character (space, tab, newline).', example: '\\s+ matches one or more spaces' },
  { char: '()', description: 'Creates a capturing group to group characters together.', example: '(abc)+ matches "abc", "abcabc"' },
  { char: '|', description: 'Acts as an OR operator (e.g., `cat|dog` matches "cat" or "dog").', example: 'apple|banana matches "apple" or "banana"' },
];

// --- Reminder Popup Function ---
function showReminderPopup(message) {
  const container = document.createElement('div');
  container.id = 'reminderPopupContainer';
  container.style.position = 'fixed';
  container.style.top = '50%';
  container.style.left = '50%';
  container.style.transform = 'translate(-50%, -50%)';
  container.style.zIndex = '10000';
  const popup = document.createElement('div');
  popup.style.background = '#23234a';
  popup.style.borderRadius = '16px';
  popup.style.boxShadow = '0 10px 32px rgba(0,0,0,0.7)';
  popup.style.padding = '2rem';
  popup.style.color = '#e0e0f0';
  popup.style.fontFamily = 'Inter, sans-serif';
  popup.style.maxWidth = '400px';
  popup.style.textAlign = 'center';
  popup.innerHTML = `
    <h3 style="color: #64ffda; margin-bottom: 1rem;">Reminder</h3>
    <p>${message}</p>
    <button id="closeReminderBtn" style="margin-top: 1rem; padding: 0.5rem 1rem; border-radius: 8px; border: none; background: #64ffda; color: #23234a; cursor: pointer;">OK</button>
  `;
  container.appendChild(popup);
  document.body.appendChild(container);
  document.getElementById('closeReminderBtn').addEventListener('click', () => {
    container.remove();
  });
}

// --- Regex Templates ---
const regexTemplates = {
  'specific-value': '',
  'sql-injection': /(SELECT|UNION|OR)\s/i,
  'xss': /<\s*script[^>]*>|<\s*\/\s*script\s*>|on(load|click|error|submit)=/i,
  'email-validation': /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  'number-validation': /^\d+$/
};

let proxyUiCreated = false; // Add a flag to prevent creating the UI multiple times
let performanceMonitorInterval = null; // Interval for monitoring proxy performance

function addDefaultProject() {
  const defaultProject = "Test Project";
  const defaultEndpoint = {
    path: "/test-endpoint",
    request: {
      headers: { whitelist: [], blacklist: [], mode: "blacklist" },
      cookies: { whitelist: [], blacklist: [], mode: "blacklist" },
      body: { whitelist: [], blacklist: [], mode: "blacklist" }
    },
    response: {
      headers: { whitelist: [], blacklist: [], mode: "blacklist" },
      cookies: { whitelist: [], blacklist: [], mode: "blacklist" },
      body: { whitelist: [], blacklist: [], mode: "blacklist" }
    }
  };

  projectNames.push(defaultProject);
  sessionEndpoints[defaultProject] = { endpoints: [defaultEndpoint] };
  saveProjects();
  saveProjectEndpoints(defaultProject);
}

// --- Data Management Functions ---
function loadProjects() {
  try {
    const raw = localStorage.getItem('projects');
    projectNames = raw ? JSON.parse(raw) : [];
  } catch (e) {
    projectNames = [];
  }
}

function saveProjects() {
  localStorage.setItem('projects', JSON.stringify(projectNames));
}

function saveProjectEndpoints(projectName) {
  if (sessionEndpoints[projectName] && sessionEndpoints[projectName].endpoints) {
    localStorage.setItem(`endpoints_${projectName}`, JSON.stringify(sessionEndpoints[projectName].endpoints));
  }
}

// --- Proxy Settings Management Functions ---
function loadProxySettings(projectName = null) {
  const key = projectName ? `proxySettings_${projectName}` : 'proxySettings';
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : {
      proxyPort: '8080',
      serverPort: '3000',
      isEnabled: false
    };
  } catch (e) {
    return {
      proxyPort: '8080',
      serverPort: '3000',
      isEnabled: false
    };
  }
}

function saveProxySettings(settings, projectName = null) {
  const key = projectName ? `proxySettings_${projectName}` : 'proxySettings';
  localStorage.setItem(key, JSON.stringify(settings));
}

function getCurrentProxySettings() {
  const proxyPortInput = document.getElementById('proxyPort');
  const serverPortInput = document.getElementById('serverPort');
  const toggleBtn = document.getElementById('toggleProxyBtn');

  return {
    proxyPort: proxyPortInput ? proxyPortInput.value : '8080',
    serverPort: serverPortInput ? serverPortInput.value : '3000',
    isEnabled: toggleBtn ? toggleBtn.textContent.includes('Disable') : false
  };
}

function loadProjectEndpoints(projectName) {
  try {
    const project676767 = currentlyEditingProject;
    const rawEndpoints = localStorage.getItem(`endpoints_${project676767}`);
    const endpoints = rawEndpoints ? JSON.parse(rawEndpoints) : [];
    sessionEndpoints[projectName] = { endpoints: [] };
    endpoints.forEach(ep => {
      ep.request.headers.whitelist = ep.request.headers.whitelist.filter(item => item.key || item.value);
      ep.request.headers.blacklist = ep.request.headers.blacklist.filter(item => item.key || item.value);
      ep.request.cookies.whitelist = ep.request.cookies.whitelist.filter(item => item.key || item.value);
      ep.request.cookies.blacklist = ep.request.cookies.blacklist.filter(item => item.key || item.value);
    });
    sessionEndpoints[projectName].endpoints = endpoints;
  } catch (error) {
    console.error(`Failed to load endpoints for project ${projectName}:`, error);
    sessionEndpoints[projectName] = { endpoints: [] };
  }
}

// --- UI Rendering Functions ---
function showFeedback(message) {
  feedbackDisplay.textContent = message;
  feedbackDisplay.style.display = 'block';
  setTimeout(() => {
    feedbackDisplay.style.display = 'none';
  }, 3000);
}

function showAlert(message) {
  showFeedback(message);
}

function renderProjectsList() {
  projectsList.innerHTML = '';
  if (projectNames.length === 0) {
    projectsList.innerHTML = '<p>No projects added yet.</p>';
    return;
  }
  projectNames.forEach(name => {
    const card = document.createElement('div');
    card.className = 'project-card';

    // Add a visual indicator if this is the currently edited project
    if (name === currentlyEditingProject) {
      card.style.border = '2px solid #64ffda';
      card.style.boxShadow = '0 0 10px rgba(100, 255, 218, 0.5)';
    }

    card.innerHTML = `
      <h3>${name}</h3>
      <div style="display: flex; gap: 0.5rem;">
        <button class="small-btn enter-edit-btn" data-project="${name}">Enter Edit Mode</button>
        <button class="small-btn btn-danger delete-btn" data-project="${name}">Delete</button>
      </div>
    `;
    projectsList.appendChild(card);
  });
}

function renderEndpoints(projectName) {
  endpointsList.innerHTML = '';
  const eps = sessionEndpoints[currentlyEditingProject]?.endpoints || [];
  if (eps.length === 0) {
    endpointsList.innerHTML = '<li>No endpoints added yet.</li>';
    return;
  }
  eps.forEach((ep) => {
    const li = document.createElement('li');
    li.dataset.endpointPath = ep.path;

    const endpointPathSpan = document.createElement('span');
    endpointPathSpan.textContent = ep.path;
    li.appendChild(endpointPathSpan);

    const buttonGroup = document.createElement('div');
    buttonGroup.className = 'endpoint-actions';

    const editBtn = document.createElement('button');
    editBtn.textContent = 'Edit';
    editBtn.className = 'small-btn btn-primary';
    editBtn.onclick = (e) => {
      e.stopPropagation();
      selectedEndpoint = sessionEndpoints[currentlyEditingProject].endpoints.find(item => item.path === ep.path);
      selectedEndpointPath = ep.path;
      localStorage.setItem('selectedEndpointPath', selectedEndpointPath);

      document.querySelectorAll('#endpointsList li').forEach(item => item.classList.remove('selected-endpoint'));
      li.classList.add('selected-endpoint');

      renderEndpointSettings(selectedEndpoint);
      endpointSettingsSection.classList.remove('hidden');
    };

    const delBtn = document.createElement('button');
    delBtn.textContent = 'X';
    delBtn.className = 'small-btn btn-danger';
    delBtn.onclick = (e) => {
      e.stopPropagation();
      projectName = currentlyEditingProject;




      if (!sessionEndpoints[projectName]) {
        console.warn("Project missing, initializing:", projectName);
        sessionEndpoints[projectName] = { endpoints: [] };
      }


      sessionEndpoints[projectName].endpoints =
        sessionEndpoints[projectName].endpoints.filter(e => {
          const match =
            e.method === ep.method &&
            e.path === ep.path;



          return !match;
        });



      saveProjectEndpoints(projectName);

      const proxySettings = loadProxySettings(currentlyEditingProject);
      updateCurrentProjectFile(
        currentlyEditingProject,
        sessionEndpoints[currentlyEditingProject].endpoints,
        proxySettings.isEnabled
      );

      reloadProxyEndpoints();

      if (selectedEndpoint && selectedEndpoint.path === ep.path) {
        console.log("Clearing selected endpoint:", selectedEndpoint);
        selectedEndpoint = null;
        selectedEndpointPath = null;
        localStorage.removeItem('selectedEndpointPath');
        endpointSettingsSection.classList.add('hidden');
      }

      renderEndpoints(projectName);
      console.groupEnd();
    };


    buttonGroup.appendChild(editBtn);
    buttonGroup.appendChild(delBtn);
    li.appendChild(buttonGroup);
    endpointsList.appendChild(li);
  });
}

// Add these lines at the very top of your script, before any functions.
let proxyProcess = null;

// Proxy state persistence functions
function saveProxyState(isRunning, port = null, project = null, serverPort = null) {
  const state = {
    isRunning: isRunning,
    port: port,
    project: project,
    serverPort: serverPort,
    timestamp: Date.now()
  };
  localStorage.setItem('proxyState', JSON.stringify(state));
  console.log('Saved proxy state:', state);
}



function clearProxyState() {
  localStorage.removeItem('proxyState');
}





// Function to update status display by fetching from API
async function updateStatusDisplay() {
  try {
    const proxyPort = document.getElementById('proxyPort').value;
    const response = await fetch(`http://localhost:${proxyPort}/api/proxy/status`);
    if (response.ok) {
      const data = await response.json();
      // Only show active if the proxy is running for the currently editing project
      const isActiveForCurrent = data.isRunning && data.project === currentlyEditingProject;
      updateProxyUI(isActiveForCurrent);
      // Sync localStorage with server state only if it's for the current project
      if (currentlyEditingProject && data.project === currentlyEditingProject) {
        const settings = loadProxySettings(currentlyEditingProject);
        settings.isEnabled = data.enabled;
        settings.proxyPort = data.proxyPort;
        settings.serverPort = data.serverPort;
        saveProxySettings(settings, currentlyEditingProject);
      }
    } else {
      console.log('Failed to fetch status');
    }
  } catch (err) {
    console.log('Error fetching status:', err);
  }
}

// Centralized function to update the proxy UI state.
function updateProxyUI(isActive) {
  const toggleBtn = document.getElementById('toggleProxyBtn');
  const statusText = document.getElementById('proxyStatusText');
  const statusIndicator = document.getElementById('proxyStatusIndicator');
  const proxyProjectDisplay = document.getElementById('proxyProjectDisplay');
  const performanceStatus = document.getElementById('proxyPerformanceStatus');

  if (!toggleBtn || !statusText || !statusIndicator) {
    return;
  }

  // Get configured ports from localStorage: use active project if proxy is running, else current project
  const projectForSettings = isActive ? proxyActiveProject : currentlyEditingProject;
  const settings = projectForSettings ?
    loadProxySettings(projectForSettings) :
    { proxyPort: '8080', serverPort: '3000' };

  const configuredProxyPort = settings.proxyPort;
  const configuredServerPort = settings.serverPort;

  if (isActive) {
    toggleBtn.textContent = 'Disable in Browser';
    toggleBtn.className = 'toggle-btn disable-proxy';
    toggleBtn.disabled = window.require ? true : false;
    toggleBtn.style.display = 'block';
    statusText.textContent = `Status: Active on Port ${configuredProxyPort}, forwarding to ${configuredServerPort}`;
    statusIndicator.style.backgroundColor = '#4CAF50';

    if (proxyProjectDisplay) {
      proxyProjectDisplay.textContent = `Proxy Project: ${currentlyEditingProject}`;
      proxyProjectDisplay.style.display = 'block';
    }

    // Start performance monitoring
    startPerformanceMonitoring(configuredProxyPort);

    // Save state with the active project
    saveProxyState(true, configuredProxyPort, proxyActiveProject, configuredServerPort);
  } else {
    toggleBtn.textContent = 'Enable Proxy';
    toggleBtn.className = 'toggle-btn enable-proxy';
    toggleBtn.disabled = false;
    toggleBtn.style.display = 'block';
    statusText.textContent = `Status: Inactive (Proxy Port: ${configuredProxyPort}, Server Port: ${configuredServerPort})`;
    statusIndicator.style.backgroundColor = '#ff5757';

    if (proxyProjectDisplay) {
      proxyProjectDisplay.style.display = 'none';
    }

    // Stop performance monitoring
    stopPerformanceMonitoring();

    if (performanceStatus) {
      performanceStatus.textContent = 'Performance: Not monitoring';
    }

    // Ensure localStorage reflects the disabled state
    if (currentlyEditingProject) {
      localStorage.setItem('enabled_' + currentlyEditingProject, 'false');
    }
  }
}

// Add this listener once, outside of any functions, to react to main process events.
if (window.require) {
  const { ipcRenderer } = window.require('electron');
  ipcRenderer.on('proxy-state-update', (event, data) => {
    const isActiveForCurrent = data.isActive && (proxyActiveProject === currentlyEditingProject);
    updateProxyUI(isActiveForCurrent);
    if (!data.isActive) {
      showFeedback('Proxy has been stopped.');
      localStorage.setItem('supabaseConnected_' + currentlyEditingProject, 'false');
      document.getElementById('connStatus').textContent = 'Not connected to Supabase';
      document.getElementById('connStatus').style.color = '#ff5757';
    }
  });
  ipcRenderer.on('proxy-stopped', () => {
    proxyProcess = null;
    proxyActiveProject = null;
    updateProxyUI(false);
    clearProxyState();
    showFeedback('Proxy has been stopped.');
    localStorage.setItem('supabaseConnected_' + currentlyEditingProject, 'false');
    document.getElementById('connStatus').textContent = 'Not connected to Supabase';
    document.getElementById('connStatus').style.color = '#ff5757';
  });
}

function switchTab(tabId) {
  // Deactivate all tab buttons and content sections
  tabButtons.forEach(b => b.classList.remove('active'));
  tabContents.forEach(t => t.classList.remove('active'));

  // Activate the selected tab button and content section
  const newActiveBtn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
  newActiveBtn.classList.add('active');
  document.getElementById(tabId).classList.add('active');

  // Handle specific tab logic
  if (tabId === 'proxy') {
    // Always regenerate the proxy UI when switching to the proxy tab
    const proxyTab = document.getElementById('proxy');
    proxyTab.innerHTML = ''; // Clear previous content

    // Create the container element for the entire proxy UI
    const proxyContainer = document.createElement('div');
    proxyContainer.className = 'proxy-container';

    // Add CSS for styling. This is a self-contained solution.
    const style = document.createElement('style');
    style.innerHTML = `
            .proxy-container {
                background: linear-gradient(145deg, #2a2a44, #20203a);
                padding: 2.5rem;
                border-radius: 16px;
                box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
                max-width: 800px;
                min-width: 370px;
                margin: 2rem auto 2rem auto;
                color: #e0e0f0;
                font-family: 'Inter', sans-serif;
                min-height: 600px;
                display: flex;
                flex-direction: column;
                gap: 24px;
                animation: fadeIn 0.5s ease-in-out;
            }

            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(20px); }
                to { opacity: 1; transform: translateY(0); }
            }

            .proxy-title {
                text-align: center;
                color: #64ffda;
                margin-bottom: 24px;
                font-size: 2.2rem;
                font-weight: bold;
                letter-spacing: 0.04em;
            }

            .proxy-status-section {
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
                margin-bottom: 1rem;
            }

            .proxy-status-indicator {
                width: 15px;
                height: 15px;
                border-radius: 50%;
                background-color: #ff5757; /* Red for inactive */
                box-shadow: 0 0 7px #c30000;
            }

            .proxy-status-text {
                font-size: 1.24em;
                font-weight: bold;
            }

            .toggle-btn {
                padding: 17px 40px;
                font-size: 1.2rem;
                border: none;
                border-radius: 10px;
                cursor: pointer;
                transition: all 0.3s cubic-bezier(.55,.23,.73,.77);
                text-align: center;
                display: block;
                margin: 24px auto 1.5rem auto;
                font-weight: bold;
                box-shadow: 0 4px 16px rgba(60,100,130,0.18);
            }
            
            .toggle-btn:disabled {
                background-color: #5a5a5a !important;
                cursor: not-allowed;
            }

            .enable-proxy {
                background-color: #4CAF50;
                color: white;
            }
            
            .enable-proxy:hover {
                background-color: #45a049;
                transform: translateY(-2px);
            }
            
            .disable-proxy {
                background-color: #ff5757;
                color: white;
            }

            .disable-proxy:hover {
                background-color: #e55353;
                transform: translateY(-2px);
            }
            
            .input-group {
                display: flex;
                flex-direction: column;
                gap: 10px;
                margin-bottom: 18px;
            }
            
            .form-input {
                padding: 13px 10px;
                border-radius: 9px;
                border: 1px solid #444;
                background-color: #222639;
                color: #eee;
                font-size: 1em;
                transition: border-color 0.22s;
                margin-bottom: 0.2em;
            }
            
            .form-input:focus {
                outline: none;
                border-color: #64ffda;
            }

            .action-buttons {
                display: flex;
                justify-content: space-around;
                gap: 14px;
                margin: 12px 0 6px 0;
            }

            .btn-primary, .btn-secondary {
                padding: 12px 23px;
                border-radius: 9px;
                cursor: pointer;
                border: none;
                font-weight: bold;
                transition: transform 0.22s;
            }

            .btn-primary {
                background-color: #007bff;
                color: white;
            }

            .btn-primary:hover {
                background-color: #0056b3;
            }

            .btn-secondary {
                background-color: #6c757d;
                color: white;
            }

            .btn-secondary:hover {
                background-color: #5a6268;
            }

            .rules-section {
                background-color: rgba(30, 33, 45, 0.22);
                padding: 19px 20px;
                border-radius: 13px;
                margin-bottom: 2em;
            }
            
            .rules-list {
                list-style-type: none;
                padding: 0;
                margin: 0;
            }

            .rules-list-item {
                padding: 11px;
                border-bottom: 1px solid #444;
                cursor: pointer;
                transition: background-color 0.21s;
                border-radius: 8px;
            }

            .rules-list-item:hover {
                background-color: rgba(255, 255, 255, 0.09);
            }
            
            .rules-list-item:last-child {
                border-bottom: none;
            }
            
            .details-popup {
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: #1e1e2d;
                color: #e0e0f0;
                padding: 2.5rem;
                border-radius: 16px;
                box-shadow: 0 15px 30px rgba(0, 0, 0, 0.7);
                z-index: 1000;
                max-width: 90vw;
                width: 500px;
                max-height: 80vh;
                overflow-y: auto;
                display: none; /* Initially hidden */
                flex-direction: column;
                gap: 15px;
                border: 2px solid #64ffda;
            }

            .details-popup-content {
                display: flex;
                flex-direction: column;
                gap: 10px;
            }
            
            .popup-close-btn {
                position: absolute;
                top: 10px;
                right: 10px;
                background: transparent;
                border: none;
                font-size: 2rem;
                color: #64ffda;
                cursor: pointer;
                transition: transform 0.2s;
            }
            
            .popup-close-btn:hover {
                transform: scale(1.1);
            }
            
            .popup-section-title {
                color: #fff;
                font-weight: bold;
                margin-top: 15px;
                border-bottom: 1px solid #444;
                padding-bottom: 5px;
            }
            
            .popup-subsection {
                background: #2a2a44;
                padding: 10px;
                border-radius: 8px;
            }
            
            .popup-list {
                list-style-type: none;
                padding-left: 0;
                margin: 0;
            }

            .popup-list-item {
                padding: 2px 0;
                font-family: 'Courier New', monospace;
            }

            .hidden {
                display: none;
            }

            .regex-feedback {
                margin-top: 0.5rem;
                font-size: 0.9em;
            }
        `;
    document.head.appendChild(style);

    // Create a title and description for the proxy tab
    const title = document.createElement('h3');
    title.textContent = 'Defensive Proxy Configuration';
    title.className = 'proxy-title';
    proxyContainer.appendChild(title);

    // Add a clear description of what the proxy does
    const description = document.createElement('div');
    description.className = 'proxy-description';
    description.style.background = '#23234a';
    description.style.borderRadius = '10px';
    description.style.padding = '1.2rem';
    description.style.marginBottom = '1.2rem';
    description.style.color = '#e0e0f0';
    description.style.fontSize = '1.1rem';
    description.style.boxShadow = '0 2px 8px rgba(0,0,0,0.2)';
    description.innerHTML = `
            <strong>How does the Defensive Proxy work?</strong><br>
            <ul style="margin-top:0.7em;margin-bottom:0.7em;padding-left:1.2em;">
                <li><span style="color:#64ffda;font-weight:bold;">Intercepts</span> all requests that would normally go to your server.</li>
                <li><span style="color:#52d8b7;font-weight:bold;">Blocks or allows</span> requests based on your configured rules (whitelist/blacklist).</li>
                <li><span style="color:#ff5757;font-weight:bold;">Sits on the port</span> your server would normally use, then <span style="color:#64ffda;font-weight:bold;">forwards</span> allowed requests to the actual server port.</li>
                <li>Use the <strong>Proxy Port</strong> field to set the port the proxy listens on (e.g., <span style="color:#64ffda;">8080</span>).</li>
                <li>Use the <strong>Server Port</strong> field to set the port of your real server (e.g., <span style="color:#52d8b7;">3000</span>).</li>
                <li>Enable the proxy to start intercepting and filtering traffic.</li>
            </ul>
    <div style="margin-top:0.7em;color:#aaa;font-size:0.98em;">
        <span style="color:#64ffda;">Tip:</span> Point your client/app to the <strong>Proxy Port</strong> instead of the server port.<br>
        <span style="color:#ff5757;">Blocked requests</span> will not reach your server.<br>
        <span style="color:#52d8b7;">Allowed requests</span> will be forwarded to your server port.
    </div>
    <div style="margin-top:0.7em;color:#ff6b35;font-size:0.98em;background:#ff6b35;color:white;padding:0.5rem;border-radius:8px;">
        <strong>Warning:</strong> When using the proxy, always use full localhost URLs in your fetch calls, e.g., <code>fetch('http://localhost:8080/api/users')</code> instead of relative paths like <code>fetch('/api/users')</code>. This ensures requests are intercepted by the proxy on the specified port.
    </div>
        `;
    proxyContainer.appendChild(description);

    // Status section
    const statusSection = document.createElement('div');
    statusSection.className = 'proxy-status-section';
    const statusIndicator = document.createElement('div');
    statusIndicator.id = 'proxyStatusIndicator';
    statusIndicator.className = 'proxy-status-indicator';
    const statusText = document.createElement('span');
    statusText.id = 'proxyStatusText';
    statusText.className = 'proxy-status-text';
    statusText.textContent = 'Status: Inactive';
    statusSection.appendChild(statusIndicator);
    statusSection.appendChild(statusText);

    // Performance status
    const performanceStatus = document.createElement('div');
    performanceStatus.id = 'proxyPerformanceStatus';
    performanceStatus.className = 'proxy-performance-status';
    performanceStatus.style.marginTop = '10px';
    performanceStatus.style.fontSize = '0.9em';
    performanceStatus.style.color = '#64ffda';
    performanceStatus.textContent = 'Performance: Not monitoring';
    statusSection.appendChild(performanceStatus);

    // Proxy project display
    const proxyProjectDisplay = document.createElement('div');
    proxyProjectDisplay.id = 'proxyProjectDisplay';
    proxyProjectDisplay.className = 'proxy-project-display';
    proxyProjectDisplay.style.display = 'none';
    proxyProjectDisplay.style.marginTop = '10px';
    proxyProjectDisplay.style.fontSize = '0.9em';
    proxyProjectDisplay.style.color = '#64ffda';
    proxyProjectDisplay.style.fontWeight = 'bold';
    statusSection.appendChild(proxyProjectDisplay);

    proxyContainer.appendChild(statusSection);

    // Load saved proxy settings for the currently editing project
    const projectForSettings = currentlyEditingProject;
    let savedSettings = loadProxySettings(projectForSettings);

    // Toggle button
    const toggleBtn = document.createElement('button');
    toggleBtn.id = 'toggleProxyBtn';
    // Default to enable button state
    toggleBtn.textContent = 'Enable Proxy';
    toggleBtn.className = 'toggle-btn enable-proxy';
    toggleBtn.disabled = false;
    proxyContainer.appendChild(toggleBtn);

    // Form section
    const formSection = document.createElement('div');
    formSection.className = 'form-section';

    const proxyPortLabel = document.createElement('label');
    proxyPortLabel.textContent = 'Proxy Port:';
    const proxyPortInput = document.createElement('input');
    proxyPortInput.id = 'proxyPort';
    proxyPortInput.type = 'number';
    proxyPortInput.value = savedSettings.proxyPort;
    proxyPortInput.className = 'form-input';
    proxyPortInput.addEventListener('change', () => {
      const settings = getCurrentProxySettings();
      saveProxySettings(settings, projectForSettings);
    });
    formSection.appendChild(proxyPortLabel);
    formSection.appendChild(proxyPortInput);

    const serverPortLabel = document.createElement('label');
    serverPortLabel.textContent = 'Server Port:';
    const serverPortInput = document.createElement('input');
    serverPortInput.id = 'serverPort';
    serverPortInput.type = 'number';
    serverPortInput.value = savedSettings.serverPort;
    serverPortInput.className = 'form-input';
    serverPortInput.addEventListener('change', () => {
      const settings = getCurrentProxySettings();
      saveProxySettings(settings, projectForSettings);
    });
    formSection.appendChild(serverPortLabel);
    formSection.appendChild(serverPortInput);
    proxyContainer.appendChild(formSection);

    // Action buttons
    const actionButtons = document.createElement('div');
    actionButtons.className = 'action-buttons';
    const saveBtn = document.createElement('button');
    saveBtn.textContent = 'Save Settings';
    saveBtn.className = 'btn-primary';
    const resetBtn = document.createElement('button');
    resetBtn.textContent = 'Reset';
    resetBtn.className = 'btn-secondary';
    actionButtons.appendChild(saveBtn);
    actionButtons.appendChild(resetBtn);
    proxyContainer.appendChild(actionButtons);




    // HTTP Testing Section
    const testingSection = document.createElement('div');
    testingSection.className = 'testing-section';
    testingSection.style.background = '#23234a';
    testingSection.style.borderRadius = '12px';
    testingSection.style.padding = '1.5rem 2rem';
    testingSection.style.marginBottom = '2rem';
    testingSection.style.boxShadow = '0 4px 16px rgba(0,0,0,0.4)';
    testingSection.style.color = '#e0e0f0';
    testingSection.style.fontFamily = 'Inter, sans-serif';

    const testingHeader = document.createElement('h4');
    testingHeader.textContent = 'HTTP Testing';
    testingHeader.style.color = '#64ffda';
    testingHeader.style.marginBottom = '1rem';
    testingHeader.style.fontSize = '1.5rem';
    testingSection.appendChild(testingHeader);

    const testingDescription = document.createElement('p');
    testingDescription.textContent = 'Test your proxy rules by sending HTTP requests. Make sure the proxy is enabled and your server is running.';
    testingDescription.style.marginBottom = '1.5rem';
    testingDescription.style.fontSize = '0.9em';
    testingDescription.style.color = '#aaa';
    testingSection.appendChild(testingDescription);

    // Test Request Form
    const testForm = document.createElement('div');
    testForm.style.display = 'flex';
    testForm.style.flexDirection = 'column';
    testForm.style.gap = '1rem';

    // Method and URL row
    const methodUrlRow = document.createElement('div');
    methodUrlRow.style.display = 'flex';
    methodUrlRow.style.gap = '1rem';
    methodUrlRow.style.alignItems = 'center';

    const methodSelect = document.createElement('select');
    methodSelect.className = 'form-input';
    methodSelect.style.width = '120px';
    methodSelect.innerHTML = `
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
            <option value="PATCH">PATCH</option>
            <option value="HEAD">HEAD</option>
            <option value="OPTIONS">OPTIONS</option>
        `;
    methodUrlRow.appendChild(methodSelect);

    const urlInput = document.createElement('input');
    urlInput.type = 'text';
    urlInput.className = 'form-input';
    urlInput.placeholder = 'URL Path (e.g., /api/test)';
    urlInput.value = '/api/test';
    urlInput.style.flex = '1';
    methodUrlRow.appendChild(urlInput);

    testForm.appendChild(methodUrlRow);

    // Headers
    const headersLabel = document.createElement('label');
    headersLabel.textContent = 'Headers (one per line, key: value):';
    headersLabel.style.fontWeight = 'bold';
    headersLabel.style.color = '#64ffda';
    testForm.appendChild(headersLabel);

    const headersTextarea = document.createElement('textarea');
    headersTextarea.className = 'form-input';
    headersTextarea.placeholder = 'Content-Type: application/json\nAuthorization: Bearer token';
    headersTextarea.rows = 3;
    testForm.appendChild(headersTextarea);

    // Body
    const bodyLabel = document.createElement('label');
    bodyLabel.textContent = 'Request Body:';
    bodyLabel.style.fontWeight = 'bold';
    bodyLabel.style.color = '#64ffda';
    testForm.appendChild(bodyLabel);

    const bodyTextarea = document.createElement('textarea');
    bodyTextarea.className = 'form-input';
    bodyTextarea.placeholder = '{"key": "value"}';
    bodyTextarea.rows = 4;
    testForm.appendChild(bodyTextarea);

    // Send Button
    const sendTestBtn = document.createElement('button');
    sendTestBtn.textContent = 'Send Test Request';
    sendTestBtn.className = 'btn-primary';
    sendTestBtn.style.width = '200px';
    sendTestBtn.style.alignSelf = 'flex-start';
    testForm.appendChild(sendTestBtn);

    testingSection.appendChild(testForm);

    // Test Results
    const resultsSection = document.createElement('div');
    resultsSection.id = 'testResults';
    resultsSection.style.marginTop = '1.5rem';
    resultsSection.style.padding = '1rem';
    resultsSection.style.background = '#29294d';
    resultsSection.style.borderRadius = '8px';
    resultsSection.style.display = 'none';

    const resultsHeader = document.createElement('h5');
    resultsHeader.textContent = 'Test Results';
    resultsHeader.style.color = '#64ffda';
    resultsHeader.style.marginBottom = '1rem';
    resultsSection.appendChild(resultsHeader);

    const statusDiv = document.createElement('div');
    statusDiv.id = 'testStatus';
    statusDiv.style.marginBottom = '0.5rem';
    resultsSection.appendChild(statusDiv);

    const responseHeadersDiv = document.createElement('div');
    responseHeadersDiv.id = 'testResponseHeaders';
    responseHeadersDiv.style.marginBottom = '0.5rem';
    resultsSection.appendChild(responseHeadersDiv);

    const responseBodyDiv = document.createElement('div');
    responseBodyDiv.id = 'testResponseBody';
    resultsSection.appendChild(responseBodyDiv);

    testingSection.appendChild(resultsSection);

    proxyContainer.appendChild(testingSection);

    // Function to send test request
    async function sendTestRequest() {
      const proxyPort = proxyPortInput.value || '8080';
      const method = methodSelect.value;
      const urlPath = urlInput.value.trim();
      const headersText = headersTextarea.value.trim();
      const bodyText = bodyTextarea.value.trim();

      if (!urlPath) {
        showFeedback('Please enter a URL path for the test request.');
        return;
      }

      // Parse headers
      const headers = {};
      if (headersText) {
        const headerLines = headersText.split('\n');
        for (const line of headerLines) {
          const colonIndex = line.indexOf(':');
          if (colonIndex > 0) {
            const key = line.substring(0, colonIndex).trim();
            const value = line.substring(colonIndex + 1).trim();
            headers[key] = value;
          }
        }
      }

      // Prepare request options
      const requestOptions = {
        method: method,
        headers: headers,
        mode: 'cors'
      };

      if (bodyText && ['POST', 'PUT', 'PATCH'].includes(method)) {
        requestOptions.body = bodyText;
      }

      try {
        const fullUrl = `http://localhost:${proxyPort}${urlPath}`;
        console.log('Sending test request to:', fullUrl, requestOptions);

        const startTime = performance.now();
        const response = await fetch(fullUrl, requestOptions);
        const endTime = performance.now();
        const responseTime = endTime - startTime;

        // Get response headers
        const responseHeaders = {};
        for (const [key, value] of response.headers.entries()) {
          responseHeaders[key] = value;
        }

        // Get response body
        let responseBody = '';
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          try {
            responseBody = JSON.stringify(await response.json(), null, 2);
          } catch (e) {
            responseBody = await response.text();
          }
        } else {
          responseBody = await response.text();
        }

        // Display results
        statusDiv.innerHTML = `<strong>Status:</strong> ${response.status} ${response.statusText} (${Math.round(responseTime)}ms)`;
        statusDiv.style.color = response.ok ? '#4CAF50' : '#ff5757';

        responseHeadersDiv.innerHTML = `<strong>Response Headers:</strong><br><pre style="background: #1a1a2e; padding: 0.5rem; border-radius: 4px; margin-top: 0.5rem; font-size: 0.8em; overflow-x: auto;">${Object.entries(responseHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')}</pre>`;

        responseBodyDiv.innerHTML = `<strong>Response Body:</strong><br><pre style="background: #1a1a2e; padding: 0.5rem; border-radius: 4px; margin-top: 0.5rem; font-size: 0.8em; overflow-x: auto; max-height: 200px; overflow-y: auto;">${responseBody}</pre>`;

        resultsSection.style.display = 'block';
        showFeedback(`Test request sent successfully (${response.status})`);

      } catch (error) {
        console.error('Test request failed:', error);
        statusDiv.innerHTML = `<strong>Error:</strong> ${error.message}`;
        statusDiv.style.color = '#ff5757';
        responseHeadersDiv.innerHTML = '';
        responseBodyDiv.innerHTML = '';
        resultsSection.style.display = 'block';
        showFeedback('Test request failed: ' + error.message);
      }
    }

    // Event listener for send test button
    sendTestBtn.addEventListener('click', sendTestRequest);

    // Enable/disable testing based on proxy status
    function updateTestingSection() {
      const isActive = toggleBtn.textContent.includes('Disable') || toggleBtn.textContent.includes('Browser');
      sendTestBtn.disabled = !isActive;
      sendTestBtn.style.opacity = isActive ? '1' : '0.5';
      if (!isActive) {
        resultsSection.style.display = 'none';
      }
    }

    // Initial update
    updateTestingSection();

    // Update testing section when proxy state changes
    const originalUpdateProxyUI = updateProxyUI;
    updateProxyUI = function (isActive) {
      originalUpdateProxyUI(isActive);
      updateTestingSection();
    };

    saveBtn.addEventListener('click', () => {
      const settings = getCurrentProxySettings();
      const targetProject = proxyActiveProject || currentlyEditingProject;

      if (targetProject) {
        if (!sessionEndpoints[targetProject]) {
          sessionEndpoints[targetProject] = { endpoints: [] };
        }
        sessionEndpoints[targetProject].proxyPort = settings.proxyPort;
        sessionEndpoints[targetProject].serverPort = settings.serverPort;
        saveProjectEndpoints(targetProject);
        saveProxySettings(settings, targetProject);
        showFeedback(`Settings saved for project: ${targetProject}!`);
      } else {
        showFeedback('Please select a project to save settings.');
      }
    });

    resetBtn.addEventListener('click', () => {
      proxyPortInput.value = '8080';
      serverPortInput.value = '3000';
    });


    // Proxy enable feedback tracker
    let proxyEnableFeedbackShown = false;

    // Event listener for toggle button
    toggleBtn.addEventListener('click', async () => {
      if (isElectron) {
        console.log('Toggle proxy button clicked');
        const proxyPort = proxyPortInput.value || '8080';
        const serverPort = serverPortInput.value || '3000';
        console.log(`Proxy port: ${proxyPort}, Server port: ${serverPort}`);

        // Check if the app is in the Electron environment.
        if (window.require) {
          // If the proxy is not running, start it.
          if (!proxyProcess) {
            if (!currentlyEditingProject) {
              showFeedback('Please select a project before enabling proxy.');
              return;
            }

            // Check if proxy port and server port are the same
            if (proxyPort === serverPort) {
              showFeedback('Proxy port and server port cannot be the same.');
              return;
            }

            try {
              const { ipcRenderer } = window.require('electron');
              const { updateCurrentProjectFile } = require('./updateCurrentProject.js');

              // Save localStorage endpoints to JSON file before starting proxy
              if (sessionEndpoints[currentlyEditingProject] && sessionEndpoints[currentlyEditingProject].endpoints) {
                const proxySettings = loadProxySettings(currentlyEditingProject);
                updateCurrentProjectFile(currentlyEditingProject, sessionEndpoints[currentlyEditingProject].endpoints, proxySettings.isEnabled);
              }

              // Set the active project for proxy (fixed when proxy is enabled)
              proxyActiveProject = currentlyEditingProject;

              // Send IPC message to start proxy with the fixed project
              ipcRenderer.send('start-proxy', {
                projectPath: path.join(__dirname, 'application'),
                proxyPort: proxyPort,
                serverPort: serverPort,
                currentProject: proxyActiveProject
              });

              proxyProcess = true; // Indicate proxy is started

              updateProxyUI(true);
              if (!proxyEnableFeedbackShown) {
                showFeedback(`Proxy started for project: ${proxyActiveProject}! Please go to your browser to disable it.`);
                proxyEnableFeedbackShown = true;
              }


              // Save the state.
              const settings = getCurrentProxySettings();
              saveProxySettings(settings, currentlyEditingProject);

            } catch (err) {
              showFeedback('Failed to start proxy: ' + err);
            }
          }
        } else {
          // Browser environment.
          const isRunning = toggleBtn.textContent.includes('Disable');
          if (!isRunning) {
            // Browser: call backend API to enable proxy
            try {
              const res = await fetch(window.location.origin + '/api/proxy/enable', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                  proxyPort: proxyPort,
                  serverPort: serverPort,
                  project: currentlyEditingProject,
                  endpoints: sessionEndpoints[currentlyEditingProject]?.endpoints || []
                })
              });
              if (res.ok) {
                // Set the active project for proxy
                proxyActiveProject = currentlyEditingProject;
                updateProxyUI(true);
                if (!proxyEnableFeedbackShown) {
                  showFeedback('Proxy enabled!');
                  proxyEnableFeedbackShown = true;
                }
                // Save the state.
                const settings = getCurrentProxySettings();
                saveProxySettings(settings, currentlyEditingProject);
              } else {
                showFeedback('Failed to enable proxy.');
              }
            } catch (err) {
              showFeedback('Error enabling proxy: ' + err);
            }
          } else {
            // Browser: call backend API to disable proxy
            try {
              const res = await fetch(window.location.origin + '/api/proxy/disable', {
                method: 'POST'
              });
              if (res.ok) {
                proxyActiveProject = null; // Clear active project when proxy is disabled
                await updateStatusDisplay();
                clearProxyState(); // Clear proxy state on disable
                showFeedback('Proxy disabled!');

                // Save the state.
                const settings = getCurrentProxySettings();
                saveProxySettings(settings, currentlyEditingProject);
              } else {
                showFeedback('Failed to disable proxy.');
              }
            } catch (err) {
              showFeedback('Error disabling proxy: ' + err);
            }
          }
        }
      } else {
        // api call to backend for enable proxy 
        fetch('/api/proxy/enable', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            proxyPort: proxyPortInput.value || '8080',
            serverPort: serverPortInput.value || '3000',
            currentProject: currentlyEditingProject,
            endpoints: sessionEndpoints[currentlyEditingProject]?.endpoints || []
          })
        }).then(response => {
          if (response.ok) {
            proxyActiveProject = currentlyEditingProject;
            updateProxyUI(true);
            const settings = getCurrentProxySettings();
            saveProxySettings(settings, currentlyEditingProject);
            toggleBtn.disabled = true; // Disable button to prevent multiple clicks
            toggleBtn.textContent = 'Disable in browser';
            toggleBtn.color = ''
            showFeedback('Proxy enabled!');
          } else {
            showFeedback('Failed to enable proxy.');
          }
        })


      }
    });

    async function proxyStatusUpdate() {
      try {
        const proxyPort123123123 = document.getElementById('proxyPort').value;
        const response = await fetch(`http://localhost:${proxyPort123123123}/api/proxy/status`);
        const data = await response.json();

        if (data.status == "running" && data.project === currentlyEditingProject) {
          updateProxyUI(true);
          proxyEnabled = true;
        }
        else {
          updateProxyUI(false);
          proxyEnabled = false;
          localStorage.setItem('supabaseConnected_' + currentlyEditingProject, 'false');
        }

        // Check toggleBtn state AFTER updateProxyUI has set it up
        const toggleBtn = document.getElementById('toggleProxyBtn');
        if (toggleBtn) {
          if (toggleBtn.textContent.includes('Disable')) {
            toggleBtn.disabled = true;
            toggleBtn.style.color = 'gray';
          }
        }
      }
      catch (e) {
        console.log('Failed to fetch proxy status:', e);
      }
    }

    // Append the proxyContainer to the proxyTab so the UI is visible
    proxyTab.appendChild(proxyContainer);

    proxyStatusUpdate();


  }

  if (tabId === "ips") {
    document.getElementById("saveLimit").value = JSON.parse(localStorage.getItem(`ips_${currentlyEditingProject}`)).saveLimit;
    document.getElementById("autoBlock").checked = JSON.parse(localStorage.getItem(`ips_${currentlyEditingProject}`)).autoBlockEnabled;
    document.getElementById("reputationThreshold").value = JSON.parse(localStorage.getItem(`ips_${currentlyEditingProject}`)).autoBlockThreshhold;

    const autoBlockCheckbox = document.getElementById("autoBlock");
    const thresholdInput = document.getElementById("reputationThreshold");

    function updateThreshold() {
      if (!autoBlockCheckbox.checked) {
        thresholdInput.value = '0';
        thresholdInput.readOnly = true;
      } else {
        thresholdInput.readOnly = false;
      }
    }

    autoBlockCheckbox.addEventListener('change', updateThreshold);
    updateThreshold(); // Initial call

    document.getElementById('projectId').value = localStorage.getItem(`projectId_${currentlyEditingProject}`) || '';
    document.getElementById('projectPassword').value = localStorage.getItem(`projectPassword_${currentlyEditingProject}`) || '';

    if (document.getElementById('projectId').value == '' || document.getElementById('projectPassword').value == '') {
      document.getElementById('projectId').readOnly = false;
      document.getElementById('projectPassword').readOnly = false;

      document.getElementById('saveCredentialsBtn').textContent = 'Save Credentials';
    }
    else {
      document.getElementById('projectId').readOnly = true;
      document.getElementById('projectPassword').readOnly = true;

      document.getElementById('saveCredentialsBtn').textContent = 'Edit Credentials';
    }

    if (localStorage.getItem(`supabaseConnected_${currentlyEditingProject}`) == 'true') {
      document.getElementById('connStatus').textContent = 'Connected to Supabase';
      document.getElementById('connStatus').style.color = '#4CAF50';
    } else {
      document.getElementById('connStatus').textContent = 'Not connected to Supabase';
      document.getElementById('connStatus').style.color = '#ff5757';
    }
    
    localStorage.getItem('redisSettings_' + currentlyEditingProject);
    document.getElementById('redisHost').value = JSON.parse(localStorage.getItem('redisSettings_' + currentlyEditingProject))?.host || '';
    document.getElementById('redisPort').value = JSON.parse(localStorage.getItem('redisSettings_' + currentlyEditingProject))?.port || '';
    document.getElementById('redisPassword').value = JSON.parse(localStorage.getItem('redisSettings_' + currentlyEditingProject))?.password || '';
    document.getElementById('redisUsername').value = JSON.parse(localStorage.getItem('redisSettings_' + currentlyEditingProject))?.username || '';
    document.getElementById('redisDatabase').value = JSON.parse(localStorage.getItem('redisSettings_' + currentlyEditingProject))?.database || '';
    document.getElementById('redisTLS').checked = JSON.parse(localStorage.getItem('redisSettings_' + currentlyEditingProject))?.tls || false;
    
    async function checkProxyEnabled() {
      const proxyPort = loadProxySettings(currentlyEditingProject).proxyPort;
      const connStatus = document.getElementById('connStatus');

      // Create an abort controller for the timeout
      const controller = new AbortController();
      const timeout = setTimeout(() => {
        controller.abort(); // abort the fetch after 2 seconds
      }, 2000);

      try {
        const response = await fetch(`http://localhost:${proxyPort}/api/proxy/status`, {
          method: 'GET',
          signal: controller.signal
        });

        const data = await response.json();

        if (data.status !== "running" || data.project !== currentlyEditingProject) {
          localStorage.setItem('supabaseConnected_' + currentlyEditingProject, 'false');
          connStatus.textContent = 'Not connected to Supabase';
          connStatus.style.color = '#ff5757';
        }
      } catch (err) {
        // Handles timeout, server offline, or JSON parse errors
        console.error('Failed to check proxy status:', err);
        localStorage.setItem('supabaseConnected_' + currentlyEditingProject, 'false');
        connStatus.textContent = 'Not connected to Supabase';
        connStatus.style.color = '#ff5757';
      } finally {
        clearTimeout(timeout); // clear the timeout if fetch completes
      }
    }
    checkProxyEnabled();
  }

  if (tabId === "endpoints") {
    endpointSettingsSection.classList.add('hidden');
    renderEndpoints();
  }

}

async function reloadProxyEndpoints() {
  const state = proxyEnabled;
  if (state != undefined) {
    if (state.isRunning && state.port) {
      try {
        await fetch(`http://localhost:${state.port}/api/reload-endpoints`, { method: 'POST' });
      } catch (e) {
        console.log('Failed to reload proxy endpoints:', e);
      }
    }
  }
}

function saveEndpointSettings() {
  if (!selectedEndpoint) return;
  saveProjectEndpoints(currentlyEditingProject);
  reloadProxyEndpoints();
}

function showRuleDetails(details, originalRule) {
  const isBody = details.dataType.toLowerCase() === 'body';
  const content = `
    <div class="popup-header">
      <h3>Rule Details</h3>
      <button class="close-btn">&times;</button>
    </div>
    <div class="popup-content">
      <p><strong>Data Type:</strong> ${details.dataType}</p>
      <p><strong>Rule Type:</strong> ${details.ruleType}</p>
      <p><strong>Scope:</strong> ${details.scope}</p>
      ${isBody ? `<p><strong>Key:</strong> <span id="popup-key">${details.key || 'N/A'}</span></p>` : ''}
      <p><strong>Value:</strong> <span id="popup-value">${details.value}</span></p>
      <p><strong>Method:</strong> <span id="popup-method">${details.isRegex ? 'Regex' : 'Specific Value'}</span></p>
      <p><strong>Date Added:</strong> ${details.dateAdded}</p>
      <p><strong>Notes:</strong> <span id="popup-notes">${details.notes || 'No notes.'}</span></p>
    </div>
    <div class="popup-actions">
        <button id="editRuleBtn" class="small-btn btn-primary">Edit</button>
    </div>
    <div class="popup-content">
      <h4>Configuration Rules</h4>
      <p>Here are the configuration rules for this endpoint:</p>
      <ul>
        <li><strong>Path:</strong> ${selectedEndpoint.path}</li>
        <li><strong>Request Headers Mode:</strong> ${selectedEndpoint.request.headers.mode}</li>
        <li><strong>Request Headers Whitelist:</strong> ${JSON.stringify(selectedEndpoint.request.headers.whitelist)}</li>
        <li><strong>Request Headers Blacklist:</strong> ${JSON.stringify(selectedEndpoint.request.headers.blacklist)}</li>
        <li><strong>Request Cookies Mode:</strong> ${selectedEndpoint.request.cookies.mode}</li>
        <li><strong>Request Cookies Whitelist:</strong> ${JSON.stringify(selectedEndpoint.request.cookies.whitelist)}</li>
        <li><strong>Request Cookies Blacklist:</strong> ${JSON.stringify(selectedEndpoint.request.cookies.blacklist)}</li>
        <li><strong>Request Body Mode:</strong> ${selectedEndpoint.request.body.mode}</li>
        <li><strong>Request Body Whitelist:</strong> ${JSON.stringify(selectedEndpoint.request.body.whitelist)}</li>
        <li><strong>Request Body Blacklist:</strong> ${JSON.stringify(selectedEndpoint.request.body.blacklist)}</li>
        <li><strong>Response Headers Mode:</strong> ${selectedEndpoint.response.headers.mode}</li>
        <li><strong>Response Headers Whitelist:</strong> ${JSON.stringify(selectedEndpoint.response.headers.whitelist)}</li>
        <li><strong>Response Headers Blacklist:</strong> ${JSON.stringify(selectedEndpoint.response.headers.blacklist)}</li>
        <li><strong>Response Cookies Mode:</strong> ${selectedEndpoint.response.cookies.mode}</li>
        <li><strong>Response Cookies Whitelist:</strong> ${JSON.stringify(selectedEndpoint.response.cookies.whitelist)}</li>
        <li><strong>Response Cookies Blacklist:</strong> ${JSON.stringify(selectedEndpoint.response.cookies.blacklist)}</li>
        <li><strong>Response Body Mode:</strong> ${selectedEndpoint.response.body.mode}</li>
        <li><strong>Response Body Whitelist:</strong> ${JSON.stringify(selectedEndpoint.response.body.whitelist)}</li>
        <li><strong>Response Body Blacklist:</strong> ${JSON.stringify(selectedEndpoint.response.body.blacklist)}</li>
      </ul>
    </div>
  `;
  detailsPopup.innerHTML = content;
  detailsPopup.classList.remove('hidden');

  detailsPopup.querySelector('.close-btn').addEventListener('click', hideRuleDetails);
  document.addEventListener('keydown', handleEscapeKey);

  detailsPopup.querySelector('#editRuleBtn').addEventListener('click', () => {
    editRuleDetails(originalRule, details.dataType, details.scope.toLowerCase(), details.ruleType.toLowerCase());
  });
}

function editRuleDetails(rule, dataType, scope, listType) {
  const isBody = dataType.toLowerCase() === 'body';
  const content = `
    <div class="popup-header">
      <h3>Edit Rule</h3>
      <button class="close-btn">&times;</button>
    </div>
    <div class="popup-content">
      <p><strong>Data Type:</strong> ${dataType}</p>
      <p><strong>Rule Type:</strong> ${listType === 'whitelist' ? 'Allowed' : 'Blocked'}</p>
      <p><strong>Scope:</strong> ${scope.charAt(0).toUpperCase() + scope.slice(1)}</p>
      ${isBody ? `
      <div class="form-group">
        <label for="edit-key-input">${dataType === 'headers' ? 'Header Name' : dataType === 'cookies' ? 'Cookie Name' : 'Key'}</label>
        <input type="text" id="edit-key-input" class="form-input" value="${rule.key || ''}" placeholder="${dataType === 'headers' ? 'Header Name (optional)' : dataType === 'cookies' ? 'Cookie Name (optional)' : 'Key (required)'}">
      </div>
      <div class="form-group">
        <label for="edit-value-input">Value</label>
        <input type="text" id="edit-value-input" class="form-input" value="${rule.value}">
      </div>
      <div class="form-group">
        <label for="edit-method-select">Method</label>
        <select id="edit-method-select" class="form-input">
          <option value="value" ${rule.ruleType === 'value' ? 'selected' : ''}>Specific Value</option>
          <option value="regex" ${rule.ruleType === 'regex' ? 'selected' : ''}>Regex Pattern</option>
        </select>
      </div>
      <div class="form-group">
        <label for="edit-notes-input">Notes</label>
        <textarea id="edit-notes-input" class="form-input">${rule.notes || ''}</textarea>
      </div>
    ` : ''} </div>
    <div class="popup-actions">
      <button id="saveChangesBtn" class="small-btn btn-primary">Save Changes</button>
      <button id="cancelEditBtn" class="small-btn btn-danger">Cancel</button>
    </div>
  `;
  detailsPopup.innerHTML = content;

  detailsPopup.querySelector('#saveChangesBtn').addEventListener('click', () => {
    const newKey = detailsPopup.querySelector('#edit-key-input').value;
    const newValue = detailsPopup.querySelector('#edit-value-input').value;
    const newMethod = detailsPopup.querySelector('#edit-method-select').value;
    const newNotes = detailsPopup.querySelector('#edit-notes-input').value;

    updateRule(rule, newKey, newValue, newMethod, newNotes, dataType, scope, listType);
  });

  detailsPopup.querySelector('#cancelEditBtn').addEventListener('click', () => {
    hideRuleDetails();
  });

  detailsPopup.querySelector('.close-btn').addEventListener('click', hideRuleDetails);
  document.addEventListener('keydown', handleEscapeKey);
}

function updateRule(originalRule, newKey, newValue, newMethod, newNotes, dataType, scope, listType) {
  if (!selectedEndpoint) return;

  const ruleList = selectedEndpoint[scope][dataType][listType];
  const index = ruleList.findIndex(item => item.key === originalRule.key && item.value === originalRule.value);

  if (index !== -1) {
    ruleList[index].key = newKey;
    ruleList[index].value = newValue;
    ruleList[index].ruleType = newMethod;
    ruleList[index].notes = newNotes;
    showAlert('Rule updated successfully!');
    saveEndpointSettings();
    renderEndpointSettings(selectedEndpoint);
    hideRuleDetails();
  } else {
    showAlert('Error: Rule not found.');
  }
}

function hideRuleDetails() {
  detailsPopup.classList.add('hidden');
  document.removeEventListener('keydown', handleEscapeKey);
}

function handleEscapeKey(e) {
  if (e.key === 'Escape' || e.key === 'Esc') {
    hideRuleDetails();
  }
}

function renderEndpointSettings(endpoint) {
  endpointSettingsSection.innerHTML = '';

  if (!endpoint) {
    endpointSettingsSection.classList.add('hidden');
    return;
  }

  endpoint.request = endpoint.request || {};
  endpoint.request.headers = endpoint.request.headers || { whitelist: [], blacklist: [], mode: 'blacklist' };
  endpoint.request.cookies = endpoint.request.cookies || { whitelist: [], blacklist: [], mode: 'blacklist' };
  endpoint.request.body = endpoint.request.body || { whitelist: [], blacklist: [], mode: 'blacklist' };

  endpoint.response = endpoint.response || {};
  endpoint.response.headers = endpoint.response.headers || { whitelist: [], blacklist: [], mode: 'blacklist' };
  endpoint.response.cookies = endpoint.response.cookies || { whitelist: [], blacklist: [], mode: 'blacklist' };
  endpoint.response.body = endpoint.response.body || { whitelist: [], blacklist: [], mode: 'blacklist' };

  const settingsHeader = document.createElement('h3');
  settingsHeader.textContent = `Settings for: ${endpoint.path}`;
  endpointSettingsSection.appendChild(settingsHeader);

  const modeExplanation = document.createElement('p');
  modeExplanation.style.marginBottom = '1.5rem';
  modeExplanation.innerHTML = `
    Select a rule mode to determine how this endpoint will handle requests.
    **Whitelist** mode operates as a "default pass," allowing all requests except those that explicitly match a rule.
    **Blacklist** mode operates as a "default block," only allowing requests that explicitly match a rule.
  `;
  endpointSettingsSection.appendChild(modeExplanation);

  const editTabs = document.createElement('div');
  editTabs.className = 'edit-tabs';
  editTabs.innerHTML = `
    <button class="edit-tab-btn active" data-type="request">Request Rules</button>
  `;
  endpointSettingsSection.appendChild(editTabs);

  const detailContainer = document.createElement('div');
  detailContainer.id = 'config-detail-container';
  endpointSettingsSection.appendChild(detailContainer);

  function renderDetailView(type = 'request') {
    detailContainer.innerHTML = '';
    const ruleTypes = ['headers', 'cookies', 'body'];

    const ruleTypeBlocks = document.createElement('div');
    ruleTypeBlocks.className = 'rule-type-list';

    ruleTypes.forEach(dataType => {
      const ruleTypeBlock = document.createElement('div');
      ruleTypeBlock.className = 'rule-type-block';
      ruleTypeBlock.innerHTML = `<h4>${dataType.charAt(0).toUpperCase() + dataType.slice(1)} Rules</h4>`;

      const modeControl = document.createElement('div');
      modeControl.className = 'mode-control';
      modeControl.innerHTML = `
        <label for="mode-select-${type}-${dataType}">Rule Mode:</label>
        <select id="mode-select-${type}-${dataType}" class="form-input">
          <option value="blacklist">Blacklist (Default Block)</option>
          <option value="whitelist">Whitelist (Default Pass)</option>
        </select>
      `;
      const modeSelect = modeControl.querySelector('select');
      modeSelect.value = endpoint[type][dataType].mode;
      modeSelect.addEventListener('change', (e) => {
        endpoint[type][dataType].mode = e.target.value;
        saveEndpointSettings();
        showFeedback('Rule mode updated successfully!');
      });
      ruleTypeBlock.appendChild(modeControl);

      const addRuleGroup = document.createElement('div');
      addRuleGroup.className = 'add-rule-group';

      const isBody = dataType === 'body';

      // Key Method dropdown
      const ruleKeyMethodSelect = document.createElement('select');
      ruleKeyMethodSelect.className = 'form-input';
      ruleKeyMethodSelect.style.width = '100%';
      ruleKeyMethodSelect.style.marginBottom = '0.4em';
      ruleKeyMethodSelect.innerHTML = `
      <option value="value">Specific Name</option>
      <option value="regex">Regex Pattern</option>
      `;
      addRuleGroup.appendChild(ruleKeyMethodSelect);
      // Key input (header/cookie name)
      const ruleKeyInput = document.createElement('input');
      ruleKeyInput.type = 'text';
      ruleKeyInput.className = 'form-input rule-key-input';
      ruleKeyInput.style.width = '100%';
      ruleKeyInput.style.marginBottom = '0.25em';
      ruleKeyInput.placeholder = dataType === 'headers'
        ? 'Header Name (optional)'
        : dataType === 'cookies'
          ? 'Cookie Name (optional)'
          : 'Key (optional)';
      addRuleGroup.appendChild(ruleKeyInput);
      // Regex validation for key -- placed right below the name input
      const regexKeyValidationFeedback = document.createElement('div');
      regexKeyValidationFeedback.className = 'regex-feedback hidden';
      regexKeyValidationFeedback.style.margin = '0 0 0.25em 0';
      regexKeyValidationFeedback.style.fontSize = '0.96em';
      ruleKeyInput.insertAdjacentElement('afterend', regexKeyValidationFeedback);

      // Value Method dropdown
      const ruleTypeSelect = document.createElement('select');
      ruleTypeSelect.className = 'form-input';
      ruleTypeSelect.style.width = '100%';
      ruleTypeSelect.style.marginBottom = '0.4em';
      ruleTypeSelect.innerHTML = `
      <option value="value">Specific Value</option>
      <option value="regex">Regex Pattern</option>
      `;
      addRuleGroup.appendChild(ruleTypeSelect);
      // Value/Pattern input
      const ruleValueInput = document.createElement('input');
      ruleValueInput.type = 'text';
      ruleValueInput.className = 'form-input';
      ruleValueInput.style.width = '100%';
      ruleValueInput.style.marginBottom = '0.7em';
      ruleValueInput.placeholder = 'Value/Pattern (optional)';
      addRuleGroup.appendChild(ruleValueInput);
      // Regex validation for value (positioned directly after value input)
      const regexValueValidationFeedback = document.createElement('div');
      regexValueValidationFeedback.className = 'regex-feedback hidden';
      regexValueValidationFeedback.style.margin = '0 0 0.25em 0';
      regexValueValidationFeedback.style.fontSize = '0.96em';
      ruleValueInput.insertAdjacentElement('afterend', regexValueValidationFeedback);

      // Regex template/help only for regex mode (for value)
      const regexTemplateGroup = document.createElement('div');
      regexTemplateGroup.className = 'form-group hidden';
      regexTemplateGroup.style.width = '100%';
      regexTemplateGroup.innerHTML = `
      <label for="regex-template-select-${type}-${dataType}">Value Templates:</label>
      <div style="display: flex; gap: 0.5rem;">
      <select id="regex-template-select-${type}-${dataType}" class="form-input">
      <option value="">Select a template...</option>
      <option value="sql-injection">SQL Injection</option>
      <option value="xss">Cross-Site Scripting (XSS)</option>
      <option value="email-validation">Email Validation</option>
      <option value="number-validation">Number Validation</option>
      </select>
      <button class="small-btn btn-primary" id="apply-template-btn-${type}-${dataType}">Apply</button>
      </div>
      `;
      addRuleGroup.appendChild(regexTemplateGroup);

      // Now explanation updated for convenience
      const explanation = document.createElement('p');
      if (dataType === 'headers') {
        explanation.textContent = 'Add a header name to blacklist/whitelist that header (all values optional). Enter a value or a regex pattern to further target specific values (and select pattern type).';
      } else if (dataType === 'cookies') {
        explanation.textContent = 'Add a cookie name to blacklist/whitelist that cookie (all values optional). Enter a value or a regex pattern to further target specific values.';
      } else {
        explanation.textContent = 'Add a key and or a value as in headers/cookies.';
      }
      explanation.style.fontSize = '0.9em';
      explanation.style.color = '#aaa';
      explanation.style.marginTop = '0.5rem';
      addRuleGroup.appendChild(explanation);

      // Add example regex section
      const exampleSection = document.createElement('div');
      exampleSection.style.marginTop = '1rem';
      exampleSection.style.padding = '0.5rem';
      exampleSection.style.background = '#29294d';
      exampleSection.style.borderRadius = '6px';
      exampleSection.style.fontSize = '0.9em';
      exampleSection.style.color = '#e0e0f0';
      exampleSection.innerHTML = `<strong style="color: #64ffda;">Example Regex:</strong><br>`;
      if (dataType === 'headers') {
        exampleSection.innerHTML += `Block User-Agent with 'bot': <code style="background: #1a1a2e; padding: 2px 4px; border-radius: 3px;">^.*bot.*$</code><br>Allow only JSON Content-Type: <code style="background: #1a1a2e; padding: 2px 4px; border-radius: 3px;">^application/json$</code>`;
      } else if (dataType === 'cookies') {
        exampleSection.innerHTML += `Block session cookies: <code style="background: #1a1a2e; padding: 2px 4px; border-radius: 3px;">^session.*$</code><br>Allow only secure cookies: <code style="background: #1a1a2e; padding: 2px 4px; border-radius: 3px;">^.*;.*Secure.*$</code>`;
      } else { // body
        exampleSection.innerHTML += `Block SQL injection: <code style="background: #1a1a2e; padding: 2px 4px; border-radius: 3px;">(SELECT|UNION|DROP)</code><br>Allow only alphanumeric: <code style="background: #1a1a2e; padding: 2px 4px; border-radius: 3px;">^[a-zA-Z0-9]*$</code>`;
      }
      addRuleGroup.appendChild(exampleSection);

      const regexValidationFeedback = document.createElement('div');
      regexValidationFeedback.className = 'regex-feedback hidden';
      addRuleGroup.appendChild(regexValidationFeedback);

      const regexHelpBtn = document.createElement('button');
      regexHelpBtn.textContent = 'What is Regex?';
      regexHelpBtn.className = 'small-btn btn-secondary';
      regexHelpBtn.style.display = 'none';
      addRuleGroup.appendChild(regexHelpBtn);

      regexHelpBtn.addEventListener('click', (e) => {
        e.preventDefault();
        showRegexHelp();
      });

      function showRegexHelp() {
        const helpContent = document.createElement('div');
        helpContent.style.background = '#23234a';
        helpContent.style.borderRadius = '12px';
        helpContent.style.padding = '2rem';
        helpContent.style.color = '#e0e0f0';
        helpContent.style.fontFamily = 'Inter, sans-serif';
        helpContent.style.fontSize = '1.1rem';
        helpContent.style.maxWidth = '500px';
        helpContent.style.maxHeight = '60vh';
        helpContent.style.overflowY = 'auto';
        helpContent.style.margin = '1rem auto';
        helpContent.style.boxShadow = '0 4px 16px rgba(0,0,0,0.5)';
        helpContent.innerHTML = `
              <h3 style="margin-bottom: 1rem;">Regex Help</h3>
              <ul style="margin: 1rem 0; padding-left: 1.5rem; line-height: 1.6;">
                  ${regexCharacters.map(c => `<li style="margin-bottom: 0.5rem;"><strong>${c.char}</strong>: ${c.description}<br><em>Example: ${c.example}</em></li>`).join('')}
              </ul>
              <button id="closeRegexHelpBtn" class="small-btn btn-secondary" style="margin-top: 1rem;">Close</button>
          `;

        const existingHelp = document.getElementById('regexHelpContainer');
        if (existingHelp) {
          existingHelp.remove();
        }

        const container = document.createElement('div');
        container.id = 'regexHelpContainer';
        container.style.position = 'fixed';
        container.style.top = '50%';
        container.style.left = '50%';
        container.style.transform = 'translate(-50%, -50%)';
        container.style.zIndex = '10000';
        container.appendChild(helpContent);
        document.body.appendChild(container);

        document.getElementById('closeRegexHelpBtn').addEventListener('click', () => {
          container.remove();
        });
      }

      const ruleNotesInput = document.createElement('textarea');
      ruleNotesInput.className = 'form-input';
      ruleNotesInput.placeholder = 'Add a note/comment...';
      addRuleGroup.appendChild(ruleNotesInput);

      // Key and Value dropdown event listeners for placeholder/feedback
      ruleKeyMethodSelect.addEventListener('change', () => {
        const isRegex = ruleKeyMethodSelect.value === 'regex';
        ruleKeyInput.placeholder = isRegex ? (dataType === 'headers' ? 'Header Name Regex...' : dataType === 'cookies' ? 'Cookie Name Regex...' : 'Key Regex...')
          : (dataType === 'headers' ? 'Header Name (optional)' : dataType === 'cookies' ? 'Cookie Name (optional)' : 'Key (optional)');
        regexKeyValidationFeedback.classList.add('hidden');
        if (isRegex && ruleKeyInput.value.trim() !== '') {
          if (isValidRegex(ruleKeyInput.value)) {
            regexKeyValidationFeedback.textContent = 'Valid Regex!';
            regexKeyValidationFeedback.style.color = '#64ffda';
            regexKeyValidationFeedback.classList.remove('hidden');
          } else {
            regexKeyValidationFeedback.textContent = 'Invalid Regex';
            regexKeyValidationFeedback.style.color = 'red';
            regexKeyValidationFeedback.classList.remove('hidden');
          }
        }
      });
      ruleKeyInput.addEventListener('input', () => {
        if (ruleKeyMethodSelect.value === 'regex') {
          if (isValidRegex(ruleKeyInput.value)) {
            regexKeyValidationFeedback.textContent = 'Valid Regex!';
            regexKeyValidationFeedback.style.color = '#64ffda';
            regexKeyValidationFeedback.classList.remove('hidden');
          } else {
            regexKeyValidationFeedback.textContent = 'Invalid Regex';
            regexKeyValidationFeedback.style.color = 'red';
            regexKeyValidationFeedback.classList.remove('hidden');
          }
        } else {
          regexKeyValidationFeedback.classList.add('hidden');
        }
      });
      ruleTypeSelect.addEventListener('change', () => {
        const isRegex = ruleTypeSelect.value === 'regex';
        ruleValueInput.placeholder = isRegex ? 'Regex pattern for value' : 'Value (exact substring match)';
        if (isRegex) {
          regexTemplateGroup.classList.remove('hidden');
          regexHelpBtn.style.display = 'block';
          ruleValueInput.value = '';
          regexValueValidationFeedback.textContent = '';
          regexValueValidationFeedback.classList.add('hidden');
        } else {
          regexTemplateGroup.classList.add('hidden');
          regexHelpBtn.style.display = 'none';
          regexValueValidationFeedback.classList.add('hidden');
        }
      });

      ruleValueInput.addEventListener('input', () => {
        if (ruleTypeSelect.value === 'regex') {
          if (isValidRegex(ruleValueInput.value)) {
            regexValueValidationFeedback.textContent = 'Valid Regex!';
            regexValueValidationFeedback.style.color = '#64ffda';
            regexValueValidationFeedback.classList.remove('hidden');
          } else {
            regexValueValidationFeedback.textContent = 'Invalid Regex';
            regexValueValidationFeedback.style.color = 'red';
            regexValueValidationFeedback.classList.remove('hidden');
          }
        } else {
          regexValueValidationFeedback.classList.add('hidden');
        }
      });

      const applyTemplateBtn = regexTemplateGroup.querySelector(`#apply-template-btn-${type}-${dataType}`);
      applyTemplateBtn.addEventListener('click', () => {
        const selectedTemplate = regexTemplateGroup.querySelector('select').value;
        if (selectedTemplate && regexTemplates[selectedTemplate]) {
          let templateString = regexTemplates[selectedTemplate].toString();
          templateString = templateString.replace(/^\/|\/i$/g, '');
          ruleValueInput.value = templateString;
          if (isValidRegex(templateString)) {
            regexValidationFeedback.textContent = 'Valid Regex!';
            regexValidationFeedback.style.color = '#64ffda';
            regexValidationFeedback.classList.remove('hidden');
          }
        }
      });

      const addAllowBtn = document.createElement('button');
      addAllowBtn.textContent = '+';
      addAllowBtn.className = 'small-btn';
      addAllowBtn.title = 'Add to Allowed Rules';

      const addBlockBtn = document.createElement('button');
      addBlockBtn.textContent = 'X';
      addBlockBtn.className = 'small-btn btn-danger';
      addBlockBtn.title = 'Add to Blocked Rules';

      const buttonGroup = document.createElement('div');
      buttonGroup.className = 'buttons';
      buttonGroup.appendChild(addAllowBtn);
      buttonGroup.appendChild(addBlockBtn);
      addRuleGroup.appendChild(buttonGroup);

      ruleTypeBlock.appendChild(addRuleGroup);

      const allowedList = document.createElement('ul');
      allowedList.className = 'rules-list';
      const blockedList = document.createElement('ul');
      blockedList.className = 'rules-list';

      (endpoint[type][dataType]?.whitelist || []).forEach(item => addListItem(allowedList, item, dataType, type, 'whitelist'));
      (endpoint[type][dataType]?.blacklist || []).forEach(item => addListItem(blockedList, item, dataType, type, 'blacklist'));

      ruleTypeBlock.appendChild(document.createElement('h5')).textContent = 'Allowed Rules';
      ruleTypeBlock.appendChild(allowedList);
      ruleTypeBlock.appendChild(document.createElement('h5')).textContent = 'Blocked Rules';
      ruleTypeBlock.appendChild(blockedList);

      ruleTypeBlocks.appendChild(ruleTypeBlock);

      addAllowBtn.onclick = () => {
        const key = ruleKeyInput.value;
        const ruleType = ruleTypeSelect.value;
        const keyRuleType = ruleKeyMethodSelect.value;
        const notes = ruleNotesInput.value;

        if (ruleType === 'regex' && !isValidRegex(ruleValueInput.value)) {
          showAlert('Cannot add rule: The regex pattern is invalid.');
          return;
        }

        addRule(key, ruleValueInput.value, ruleType, keyRuleType, dataType, type, 'whitelist', notes, ruleKeyInput, ruleValueInput, ruleNotesInput);
      };

      addBlockBtn.onclick = () => {
        const key = ruleKeyInput.value;
        const ruleType = ruleTypeSelect.value;
        const keyRuleType = ruleKeyMethodSelect.value;
        const notes = ruleNotesInput.value;

        if (ruleType === 'regex' && !isValidRegex(ruleValueInput.value)) {
          showAlert('Cannot add rule: The regex pattern is invalid.');
          return;
        }

        addRule(key, ruleValueInput.value, ruleType, keyRuleType, dataType, type, 'blacklist', notes, ruleKeyInput, ruleValueInput, ruleNotesInput);
      };

      // ------ update addRule signature and body accordingly...
    });

    detailContainer.appendChild(ruleTypeBlocks);
  }

  editTabs.addEventListener('click', (e) => {
    const target = e.target;
    if (target.classList.contains('edit-tab-btn')) {
      document.querySelectorAll('.edit-tab-btn').forEach(btn => btn.classList.remove('active'));
      target.classList.add('active');
      renderDetailView(target.dataset.type);
    }
  });

  renderDetailView();
}

function addRule(key, value, ruleType, keyRuleType, dataType, type, listType, notes, keyInput, valueInput, notesInput) {
  const isBody = dataType === 'body';

  // Validation
  if (!selectedEndpoint) return;
  if (!value.trim() && !key.trim()) {
    let fieldName = 'key';
    if (dataType === 'headers') fieldName = 'header name';
    else if (dataType === 'cookies') fieldName = 'cookie name';
    showAlert(`Please enter a value or ${fieldName} to add.`);
    valueInput.focus();
    return;
  }

  // Create the rule object
  const ruleObj = {
    key: (typeof key === "string" ? key.trim() : ""),
    keyRuleType: (typeof keyRuleType === "string" ? keyRuleType : "value"),
    value: (typeof value === "string" ? value.trim() : ""),
    ruleType: ruleType,
    dateAdded: new Date().toLocaleString(),
    notes: notes.trim()
  };

  // Reminder for redundant rules
  if (selectedEndpoint[type][dataType].mode === 'whitelist' && listType === 'whitelist') {
    showReminderPopup('In whitelist mode (default pass), adding to whitelist is optional since all are allowed by default.');
  }
  if (selectedEndpoint[type][dataType].mode === 'blacklist' && listType === 'blacklist') {
    showReminderPopup('In blacklist mode (default block), adding to blacklist is optional since all are blocked by default.');
  }

  const currentRules = selectedEndpoint[type][dataType][listType];
  // Check if a similar rule already exists to prevent duplicates
  const ruleExists = currentRules.some(item => {
    const keyMatch = ruleObj.key ? item.key === ruleObj.key : true;
    const valueMatch = ruleObj.value ? item.value === ruleObj.value : true;
    return keyMatch && valueMatch;
  });

  if (!ruleExists) {
    // Add the new rule and update the UI
    currentRules.push(ruleObj);
    renderEndpointSettings(selectedEndpoint);

    const feedbackMessage = `${dataType.charAt(0).toUpperCase() + dataType.slice(1)} rule added to ${listType === 'whitelist' ? 'Allowed' : 'Blocked'} rules successfully.`;
    showFeedback(feedbackMessage);
    saveEndpointSettings();

    // Clear the input fields
    valueInput.value = '';
    notesInput.value = '';
    keyInput.value = '';
    if (isBody) {
      keyInput.focus();
    } else {
      valueInput.focus();
    }
  } else {
    // Notify the user if the rule already exists
    showAlert(`This rule already exists.`);
  }
}


function addListItem(listElement, rule, dataType, type, ruleType) {
  const li = document.createElement('li');
  const isBody = dataType === 'body';
  const displayType = dataType.charAt(0).toUpperCase() + dataType.slice(1);
  const isRegex = rule.ruleType === 'regex';

  const displayKey = rule.key ? `<span style="font-weight: 600;">${rule.key}</span>: ` : '';
  ruleDetails = `${displayKey}<span style="font-style: italic;">${rule.value}</span>`;

  const ruleText = document.createElement('span');
  ruleText.className = 'rule-text';
  ruleText.innerHTML = `
      <span style="font-weight: 600; color: #64ffda; text-transform: capitalize;">${displayType}</span>: ${ruleDetails} <span style="font-size: 0.8em; color: #999;">(${isRegex ? 'regex' : 'value'})</span>
  `;
  li.appendChild(ruleText);

  const buttonGroup = document.createElement('div');
  buttonGroup.className = 'endpoint-actions';


  const viewInfoBtn = document.createElement('button');
  viewInfoBtn.textContent = 'View Info';
  viewInfoBtn.className = 'small-btn btn-primary';
  viewInfoBtn.onclick = (e) => {
    e.stopPropagation();
    // Use a single overlay and popup for all rule details
    let overlay = document.getElementById('detailsPopupOverlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'detailsPopupOverlay';
      overlay.style.position = 'fixed';
      overlay.style.top = '0';
      overlay.style.left = '0';
      overlay.style.width = '100vw';
      overlay.style.height = '100vh';
      overlay.style.background = 'rgba(20, 20, 40, 0.7)';
      overlay.style.zIndex = '9998';
      overlay.style.display = 'none';
      document.body.appendChild(overlay);
    }
    let popup = document.getElementById('detailsPopup');
    if (!popup) {
      popup = document.createElement('div');
      popup.id = 'detailsPopup';
      popup.className = 'details-popup';
      popup.style.position = 'fixed';
      popup.style.top = '50%';
      popup.style.left = '50%';
      popup.style.transform = 'translate(-50%, -50%)';
      popup.style.zIndex = '9999';
      popup.style.maxWidth = '90vw';
      popup.style.width = '500px';
      popup.style.maxHeight = '80vh';
      popup.style.overflowY = 'auto';
      popup.style.display = 'none';
      document.body.appendChild(popup);
    }

    // Determine specific labels based on dataType
    const keyLabel = dataType === 'headers' ? 'Header Name' : dataType === 'cookies' ? 'Cookie Name' : 'Key';
    const valueLabel = dataType === 'headers' ? 'Header Value' : dataType === 'cookies' ? 'Cookie Value' : 'Value';

    // Get both method types
    const keyMethodType = rule.keyRuleType || 'value';
    const valueMethodType = rule.ruleType || 'value';

    // Build rule details HTML (simple modern look)
    const content = `
    <div style="display: flex; flex-direction: column; gap: 1rem; background: #23234a; border-radius: 16px; box-shadow: 0 10px 32px rgba(0,0,0,0.7); padding: 2rem; color: #e0e0f0; font-family: 'Inter', sans-serif; position: relative;">
      <button id="popupCloseBtn" style="position: absolute; top: 10px; right: 10px; background: transparent; border: none; font-size: 2rem; color: #64ffda; cursor: pointer;">&times;</button>
      <h2 style="color: #64ffda; margin-bottom: 0.5rem;">Rule Details</h2>
      <div><strong>Data Type:</strong> ${displayType}</div>
      <div><strong>Rule Type:</strong> ${ruleType === 'whitelist' ? 'Allowed' : 'Blocked'}</div>
      <div><strong>Scope:</strong> ${type.charAt(0).toUpperCase() + type.slice(1)}</div>
      <div><strong>${keyLabel}:</strong> <input type="text" id="edit-key" value="${rule.key || ''}" style="width: 70%; padding: 0.5em; border-radius: 6px; border: 1px solid #555; background: #29294d; color: #eee;" /></div>
      <div><strong>${keyLabel} Method:</strong> <select id="edit-key-method" style="padding: 0.5em; border-radius: 6px; border: 1px solid #555; background: #29294d; color: #eee;">
        <option value="value" ${keyMethodType === 'value' ? 'selected' : ''}>Specific Value</option>
        <option value="regex" ${keyMethodType === 'regex' ? 'selected' : ''}>Regex Pattern</option>
      </select></div>
      <div><strong>${valueLabel}:</strong> <input type="text" id="edit-value" value="${rule.value}" style="width: 70%; padding: 0.5em; border-radius: 6px; border: 1px solid #555; background: #29294d; color: #eee;" /></div>
      <div><strong>${valueLabel} Method:</strong> <select id="edit-value-method" style="padding: 0.5em; border-radius: 6px; border: 1px solid #555; background: #29294d; color: #eee;">
        <option value="value" ${valueMethodType === 'value' ? 'selected' : ''}>Specific Value</option>
        <option value="regex" ${valueMethodType === 'regex' ? 'selected' : ''}>Regex Pattern</option>
      </select></div>
      <div><strong>Date Added:</strong> ${rule.dateAdded}</div>
      <div><strong>Notes:</strong> <textarea id="edit-notes" style="width: 80%; min-height: 60px; padding: 0.5em; border-radius: 6px; border: 1px solid #555; background: #29294d; color: #eee;">${rule.notes || ''}</textarea></div>
      <div style="display: flex; gap: 1rem; justify-content: flex-end; margin-top: 1rem;">
        <button id="saveChangesBtn" class="small-btn btn-primary">Save Changes</button>
        <button id="cancelEditBtn" class="small-btn btn-danger">Cancel</button>
      </div>
    </div>
  `;
    popup.innerHTML = content;
    overlay.style.display = 'block';
    popup.style.display = 'flex';
    // Close popup on close button, cancel button, or clicking overlay
    popup.querySelector('#popupCloseBtn').addEventListener('click', closePopup);
    popup.querySelector('#cancelEditBtn').addEventListener('click', closePopup);
    overlay.addEventListener('click', function (ev) {
      if (ev.target === overlay) closePopup();
    });
    // Escape key closes popup
    document.addEventListener('keydown', escHandler);
    function escHandler(ev) {
      if (ev.key === 'Escape') {
        closePopup();
        document.removeEventListener('keydown', escHandler);
      }
    }
    function closePopup() {
      popup.style.display = 'none';
      overlay.style.display = 'none';
      document.removeEventListener('keydown', escHandler);
    }
    // Save changes handler
    popup.querySelector('#saveChangesBtn').addEventListener('click', function (ev) {
      ev.preventDefault();
      const newKey = popup.querySelector('#edit-key').value;
      const newValue = popup.querySelector('#edit-value').value;
      const newKeyMethod = popup.querySelector('#edit-key-method').value;
      const newValueMethod = popup.querySelector('#edit-value-method').value;
      const newNotes = popup.querySelector('#edit-notes').value;
      if (newValueMethod === 'regex' && !isValidRegex(newValue)) {
        showAlert('Invalid regex pattern for value.');
        return;
      }
      if (newKeyMethod === 'regex' && newKey && !isValidRegex(newKey)) {
        showAlert('Invalid regex pattern for key.');
        return;
      }
      const ruleList = selectedEndpoint[type][dataType][ruleType];
      const idx = ruleList.findIndex(item => item.key === rule.key && item.value === rule.value);
      if (idx !== -1) {
        ruleList[idx].key = newKey;
        ruleList[idx].value = newValue;
        ruleList[idx].keyRuleType = newKeyMethod;
        ruleList[idx].ruleType = newValueMethod;
        ruleList[idx].notes = newNotes;
        saveEndpointSettings();
        renderEndpointSettings(selectedEndpoint);
        closePopup();
      } else {
        showAlert('Error: Rule not found.');
      }
    });
  };
  buttonGroup.appendChild(viewInfoBtn);

  const removeBtn = document.createElement('button');
  removeBtn.textContent = 'X';
  removeBtn.className = 'small-btn btn-danger';
  removeBtn.onclick = (e) => {
    e.stopPropagation();
    const currentRules = selectedEndpoint[type][dataType][ruleType];
    const updatedRules = currentRules.filter(item => !(item.key === rule.key && item.value === rule.value));
    selectedEndpoint[type][dataType][ruleType] = updatedRules;
    li.remove();
    showFeedback(`Rule removed.`);
    saveEndpointSettings();
  };
  buttonGroup.appendChild(removeBtn);

  li.appendChild(buttonGroup);
  listElement.appendChild(li);
}

// --- Event Handlers ---
function initializeEventHandlers() {
  folderInput.addEventListener('change', (e) => {
    console.log('Folder input change event fired');
    const files = Array.from(e.target.files || []);
    console.log('Files selected:', files.length);
    if (!files.length) {
      console.log('No files selected, returning');
      return;
    }
    const folderName = (files[0].webkitRelativePath || files[0].name).split('/')[0].trim();
    console.log('Extracted folder name:', folderName);
    if (!folderName || projectNames.includes(folderName)) {
      console.log('Invalid or duplicate folder name:', folderName);
      showAlert('Project with this name already exists or is invalid.');
      return;
    }
    console.log('Adding project:', folderName);
    projectNames.push(folderName);
    sessionEndpoints[folderName] = { endpoints: [] };
    saveProjects();
    console.log('Projects saved to localStorage');
    saveProjectEndpoints(folderName);
    console.log('Endpoints saved to localStorage for project:', folderName);
    renderProjectsList();
    currentlyEditingProject = folderName;
    localStorage.setItem('currentlyEditingProject', folderName);
    console.log('Set currently editing project to:', folderName);
    switchTab('endpoints');
    currentProjectDisplay.textContent = `Currently Editing Project: ${folderName}`;
    endpointsTab.classList.remove('hidden');
    document.getElementById('ipsTab').classList.remove('hidden');
    proxyTab.classList.remove('hidden');
    renderEndpoints(folderName);
    folderInput.value = '';
    console.log('Project added successfully and switched to edit mode');
  });

  projectsList.addEventListener('click', (e) => {
    if (e.target.classList.contains('enter-edit-btn')) {
      const projectName = e.target.dataset.project;
      currentlyEditingProject = projectName;
      localStorage.setItem('currentlyEditingProject', projectName);
      const proxySettings = loadProxySettings(projectName);
      loadProjectEndpoints(projectName);
      updateCurrentProjectFile(projectName, sessionEndpoints[projectName].endpoints, proxySettings.isEnabled);
      reloadProxyEndpoints();
      switchTab('endpoints');
      document.getElementById('ipsTab').classList.remove('hidden')
      currentProjectDisplay.textContent = `Currently Editing Project: ${projectName}`;
      endpointsTab.classList.remove('hidden');
      proxyTab.classList.remove('hidden');

      document.getElementById('blocked-ips').classList.remove('hidden');
      guideTab.classList.remove('hidden');
      renderEndpoints(projectName);
      endpointSettingsSection.classList.add('hidden');

      // Restore proxy UI state for this project
      restoreProxyStateForProject(projectName);

      // Update visual indicators for the selected project after all other updates
      renderProjectsList();

    } else if (e.target.classList.contains('delete-btn')) {
      const projectName = e.target.dataset.project;

      if (confirm(`Are you sure you want to delete the project "${projectName}"? This action cannot be undone.`)) {
        projectNames = projectNames.filter(name => name !== projectName);
        localStorage.removeItem(`endpoints_${projectName}`);
        localStorage.removeItem(`proxySettings_${projectName}`);
        saveProjects();

        if (currentlyEditingProject === projectName) {
          currentlyEditingProject = null;
          localStorage.removeItem('currentlyEditingProject');
          updateCurrentProjectFile('');
          switchTab('projects');
          currentProjectDisplay.textContent = 'Currently Editing Project: None';
          endpointsTab.classList.add('hidden');
          document.getElementById('ipsTab').classList.add('hidden')
          proxyTab.classList.add('hidden');
          document.getElementById('blocked-ips').classList.add('hidden');
          endpointSettingsSection.classList.add('hidden');
        }

        if (proxyActiveProject === projectName) {
          if (window.require) {
            const { ipcRenderer } = window.require('electron');
            ipcRenderer.send('stop-proxy');
          }
          proxyProcess = null;
          proxyActiveProject = null;
          updateProxyUI(false);
          clearProxyState();
          showFeedback('Proxy disabled because the active project was deleted.');
        }

        renderProjectsList();
        showFeedback(`Project "${projectName}" deleted successfully.`);
      }
    }
  });

  addEndpointBtn.addEventListener('click', () => {
    const project = currentlyEditingProject;
    const endpointPath = newEndpointInput.value.trim();
    if (!project || !endpointPath) {
      showAlert('Please enter an endpoint path.');
      newEndpointInput.value = '';
      newEndpointInput.focus();
      return;
    }

    if (!sessionEndpoints[project]) {
      sessionEndpoints[project] = { endpoints: [] };
    }

    const exists = sessionEndpoints[project].endpoints.some(ep => ep.path === endpointPath);

    if (!exists) {
      const obfuscatedPath = "/api/" + Math.random().toString(36).substr(2, 10) + Math.random().toString(36).substr(2, 10);
      const newEndpoint = {
        path: endpointPath,
        obfuscatedPath: obfuscatedPath,
        request: {
          headers: { whitelist: [], blacklist: [], mode: 'blacklist' },
          cookies: { whitelist: [], blacklist: [], mode: 'blacklist' },
          body: { whitelist: [], blacklist: [], mode: 'blacklist' }
        },
        response: {
          headers: { whitelist: [], blacklist: [], mode: 'blacklist' },
          cookies: { whitelist: [], blacklist: [], mode: 'blacklist' },
          body: { whitelist: [], blacklist: [], mode: 'blacklist' }
        }
      };
      sessionEndpoints[project].endpoints.push(newEndpoint);
      saveProjectEndpoints(project);
      renderEndpoints(project);
      newEndpointInput.value = '';
      showFeedback('Endpoint added successfully!');
    } else {
      showAlert('This endpoint already exists.');
      newEndpointInput.value = '';
      newEndpointInput.focus();
    }
  });

  exitEditModeBtn.addEventListener('click', () => {
    currentlyEditingProject = null;
    selectedEndpoint = null;
    selectedEndpointPath = null;
    localStorage.removeItem('currentlyEditingProject'); // Clear from local storage
    localStorage.removeItem('selectedEndpointPath');
    updateCurrentProjectFile(''); // Clear the file
    reloadProxyEndpoints();
    switchTab('projects');
    endpointsList.innerHTML = '<li>Select a project to see endpoints.</li>';
    currentProjectDisplay.textContent = 'Currently Editing Project: None';
    endpointSettingsSection.classList.add('hidden');
    document.getElementById('ipsTab').classList.add('hidden')
    endpointsTab.classList.add('hidden');
    proxyTab.classList.add('hidden');
    // guideTab remains visible
  });

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      switchTab(btn.dataset.tab);
    });
  });
}

// --- Initialization ---

// --- Global State Variables ---
let projectNames = [];
let sessionEndpoints = {};
let currentlyEditingProject = null;
let proxyActiveProject = null; // Store the project used by proxy when enabled

// Load current project from localStorage on startup
try {
  const savedProject = localStorage.getItem('currentlyEditingProject');
  if (savedProject) {
    currentlyEditingProject = savedProject;
    console.log('Loaded current project from localStorage:', currentlyEditingProject);
  }
} catch (err) {
  console.error('Failed to load current project from localStorage:', err);
}
// Load selected endpoint path
try {
  const savedPath = localStorage.getItem('selectedEndpointPath');
  if (savedPath) {
    selectedEndpointPath = savedPath;
    console.log('Loaded selected endpoint path from localStorage:', selectedEndpointPath);
  }
} catch (err) {
  console.error('Failed to load selected endpoint path from localStorage:', err);
}
let selectedEndpoint = null;

document.addEventListener('DOMContentLoaded', async () => {
  // State variables are now global
  loadProjects();
  projectNames.forEach(projectName => {
    loadProjectEndpoints(projectName);
  });
  renderProjectsList();
  initializeEventHandlers();

  // If a current project was loaded from JSON, initialize the UI accordingly
  if (currentlyEditingProject) {
    currentProjectDisplay.textContent = `Currently Editing Project: ${currentlyEditingProject}`;
    endpointsTab.classList.remove('hidden');
    document.getElementById('ipsTab').classList.remove('hidden')
    proxyTab.classList.remove('hidden');
    loadProjectEndpoints(currentlyEditingProject);
    renderEndpoints(currentlyEditingProject);
    // If there was a selected endpoint, restore it
    if (selectedEndpointPath && sessionEndpoints[currentlyEditingProject]) {
      selectedEndpoint = sessionEndpoints[currentlyEditingProject].endpoints.find(ep => ep.path === selectedEndpointPath);
      if (selectedEndpoint) {
        renderEndpointSettings(selectedEndpoint);
        endpointSettingsSection.classList.remove('hidden');
        // Highlight the selected endpoint
        document.querySelectorAll('#endpointsList li').forEach(li => {
          if (li.dataset.endpointPath === selectedEndpointPath) {
            li.classList.add('selected-endpoint');
          }
        });
      } else {
        endpointSettingsSection.classList.add('hidden');
      }
    } else {
      endpointSettingsSection.classList.add('hidden');
    }
  }


  // Start performance monitoring if proxy is active on load
  const savedProxyState = proxyEnabled;
  if (savedProxyState != undefined) {
    if (savedProxyState.isRunning && savedProxyState.port) {
      startPerformanceMonitoring(savedProxyState.port);
    }
  }

  // Tutorial button event listener
  const tutorialBtn = document.getElementById('tutorial-btn');
  if (tutorialBtn) {
    tutorialBtn.addEventListener('click', showTutorial);
  }

});


// Helper function to update proxy UI with retry mechanism
function updateProxyUIWithRetry(isActive) {
  const maxRetries = 10;
  let retryCount = 0;

  const tryUpdate = () => {
    const toggleBtn = document.getElementById('toggleProxyBtn');
    const statusText = document.getElementById('proxyStatusText');
    const statusIndicator = document.getElementById('proxyStatusIndicator');

    if (toggleBtn && statusText && statusIndicator) {
      // Elements are ready, update UI
      updateProxyUI(isActive);
    } else if (retryCount < maxRetries) {
      // Elements not ready yet, retry after a short delay
      retryCount++;
      setTimeout(tryUpdate, 100);
    }
    // If max retries reached and elements still not available, give up
  };

  tryUpdate();
}

// --- Tutorial System ---
let currentTutorialStep = 0;
let tutorialCheckInterval;
let currentTimeout = null;

const tutorialConditions = [
  () => true, // Welcome
  () => Object.keys(sessionEndpoints).length > 0, // Project added
  () => currentlyEditingProject !== null, // Entered edit mode
  () => currentlyEditingProject && sessionEndpoints[currentlyEditingProject].endpoints.length > 0, // Endpoint added
  () => true, // Rules added (simplified)
  () => true, // Rules explained
  () => true, // Proxy info
  () => true // Proxy info
];

const tutorialSteps = [
  {
    title: "Welcome to SecureLink",
    text: "This app helps you create and manage defensive proxies for your web applications. It allows you to intercept, filter, and modify requests and responses based on custom rules. Let's get started!",
    highlight: null,
    statusText: "",
    action: null
  },
  {
    title: "Making Projects",
    text: "Projects organize your endpoints and rules. To create a project, click on the '+ Add Project' button and select a folder to represent your project.",
    highlight: ".add-btn",
    statusText: "Click the highlighted button to add a project.",
    action: () => document.querySelector('.add-btn').click()
  },
  {
    title: "Entering Edit Mode",
    text: "Once you have a project, click the 'Enter Edit Mode' button next to it. This will switch you to the Endpoints tab where you can manage your project's configuration.",
    highlight: null,
    statusText: "Click 'Enter Edit Mode' on your project to continue.",
    action: null
  },
  {
    title: "Adding an Endpoint",
    text: "Endpoints are the URLs you want to protect. In the Endpoints tab, enter a path like '/api/users' in the input field and click 'Add Endpoint'.",
    highlight: "#newEndpointInput",
    statusText: "Click the highlighted input to enter a path.",
    action: () => document.getElementById('newEndpointInput').focus()
  },
  {
    title: "Adding Rules",
    text: "Rules control what requests are allowed or blocked. Click 'Edit' on an endpoint to open its settings. Add a rule for headers, cookies, or body.",
    highlight: null,
    statusText: "Click 'Edit' on an endpoint and add a rule to continue.",
    action: null
  },
  {
    title: "What are Rules?",
    text: "Rules can be whitelist (default pass, block specific items) or blacklist (default block, allow specific items). Examples: Block SQL injection patterns, allow only specific headers, or filter out XSS attempts. Use regex for advanced matching.",
    highlight: null,
    statusText: "",
    action: null
  },
  {
    title: "Proxy Information",
    text: "The Proxy tab lets you configure and enable the defensive proxy. Set proxy and server ports, then enable it. The proxy will intercept requests on the proxy port and forward allowed ones to your server port.",
    highlight: ".tab-btn[data-tab='proxy']",
    statusText: "Click the highlighted tab to view proxy settings.",
    action: () => document.querySelector('.tab-btn[data-tab="proxy"]').click()
  }
];

function showTutorial() {
  const overlay = document.getElementById('tutorial-overlay');
  overlay.style.display = 'block';
  showTutorialStep(0);
  tutorialCheckInterval = setInterval(checkTutorialCondition, 1000);

  // Make tutorial modal draggable
  const modal = document.getElementById('tutorial-modal');
  // Reset position to center before making draggable
  modal.style.top = '50%';
  modal.style.left = '50%';
  modal.style.transform = 'translate(-50%, -50%)';
  modal.style.right = 'auto';
  modal.style.bottom = 'auto';
  makeDraggable(modal);
}

function makeDraggable(element) {
  let isDragging = false;
  let startX, startY, initialX, initialY;

  element.addEventListener('mousedown', (e) => {
    isDragging = true;
    startX = e.clientX;
    startY = e.clientY;
    initialX = element.offsetLeft;
    initialY = element.offsetTop;
    element.style.cursor = 'grabbing';
    e.preventDefault();
  });

  document.addEventListener('mousemove', (e) => {
    if (!isDragging) return;
    const dx = e.clientX - startX;
    const dy = e.clientY - startY;
    element.style.left = initialX + dx + 'px';
    element.style.top = initialY + dy + 'px';
    element.style.right = 'auto';
    element.style.bottom = 'auto';
  });

  document.addEventListener('mouseup', () => {
    if (isDragging) {
      isDragging = false;
      element.style.cursor = 'grab';
    }
  });

  // Set initial cursor
  element.style.cursor = 'grab';
}

function hideTutorial() {
  const overlay = document.getElementById('tutorial-overlay');
  overlay.style.display = 'none';
  hideHighlight();
}

function showTutorialStep(step) {
  currentTutorialStep = step;
  const stepData = tutorialSteps[step];
  document.getElementById('tutorial-title').textContent = stepData.title;
  document.getElementById('tutorial-text').textContent = stepData.text;
  document.getElementById('tutorial-status').textContent = stepData.statusText;
  document.getElementById('tutorial-step-indicator').textContent = `Step ${step + 1} of ${tutorialSteps.length}`;

  const prevBtn = document.getElementById('tutorial-prev');
  const nextBtn = document.getElementById('tutorial-next');

  prevBtn.style.display = step === 0 ? 'none' : 'block';
  nextBtn.textContent = step === tutorialSteps.length - 1 ? 'Finish' : 'Next';

  highlightElement(stepData.highlight);
  checkTutorialCondition();
}

function highlightElement(selector) {
  hideHighlight();
  if (!selector) return;

  const element = document.querySelector(selector);
  if (element) {
    const rect = element.getBoundingClientRect();
    const highlight = document.getElementById('highlight-overlay');
    const arrow = document.getElementById('highlight-arrow');
    highlight.style.display = 'block';
    highlight.style.top = rect.top + window.scrollY - 5 + 'px';
    highlight.style.left = rect.left - 5 + 'px';
    highlight.style.width = rect.width + 10 + 'px';
    highlight.style.height = rect.height + 10 + 'px';
    arrow.style.display = 'block';

    // Add click event for action
    const step = tutorialSteps[currentTutorialStep];
    if (step.action) {
      highlight.onclick = step.action;
    } else {
      highlight.onclick = null;
    }
  }
}

function hideHighlight() {
  document.getElementById('highlight-overlay').style.display = 'none';
}

function nextTutorialStep() {
  if (currentTutorialStep < tutorialSteps.length - 1) {
    showTutorialStep(currentTutorialStep + 1);
  } else {
    hideTutorial();
  }
}

function prevTutorialStep() {
  if (currentTutorialStep > 0) {
    showTutorialStep(currentTutorialStep - 1);
  }
}

function checkTutorialCondition() {
  const condition = tutorialConditions[currentTutorialStep];
  const met = condition();
  const nextBtn = document.getElementById('tutorial-next');
  if (met) {
    nextBtn.disabled = false;
    nextBtn.style.opacity = '1';
  } else {
    nextBtn.disabled = true;
    nextBtn.style.opacity = '0.5';
  }
}

// Tutorial event listeners
document.getElementById('tutorial-close').addEventListener('click', hideTutorial);
document.getElementById('tutorial-next').addEventListener('click', nextTutorialStep);
document.getElementById('tutorial-prev').addEventListener('click', prevTutorialStep);

// Performance monitoring functions
async function startPerformanceMonitoring(port) {
  stopPerformanceMonitoring(); // Clear any existing interval

  const performanceStatus = document.getElementById('proxyPerformanceStatus');
  if (!performanceStatus) return;

  performanceStatus.textContent = 'Performance: Checking...';

  performanceMonitorInterval = setInterval(async () => {
    try {
      const startTime = performance.now();
      const response = await fetch(`http://localhost:${port}/api/proxy/status`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000), // 5 second timeout
        headers: {
          'Accept': 'application/json'
        }
      });
      const endTime = performance.now();
      const responseTime = endTime - startTime;

      if (response.ok) {
        const data = await response.json();
        if (data.status === 'running') {
          // Determine performance status based on response time
          let performanceText = '';
          let color = '#64ffda'; // Default green

          if (responseTime < 100) {
            performanceText = 'Excellent';
            color = '#4CAF50'; // Green
          } else if (responseTime < 300) {
            performanceText = 'Good';
            color = '#64ffda'; // Cyan
          } else if (responseTime < 1000) {
            performanceText = 'Fair';
            color = '#ff9800'; // Orange
          } else if (responseTime < 3000) {
            performanceText = 'Slow';
            color = '#ff5757'; // Red
          } else {
            performanceText = 'Very Slow';
            color = '#c30000'; // Dark red
          }

          performanceStatus.textContent = `Performance: ${performanceText} (${Math.round(responseTime)}ms)`;
          performanceStatus.style.color = color;
        } else {
          performanceStatus.textContent = 'Performance: Proxy disabled';
          performanceStatus.style.color = '#ff5757';
        }
      } else {
        performanceStatus.textContent = 'Performance: Error checking status';
        performanceStatus.style.color = '#ff5757';
      }
    } catch (error) {
      console.log('Performance check failed:', error.message);
      performanceStatus.textContent = 'Performance: Unable to check';
      performanceStatus.style.color = '#ff5757';
    }
  }, 5000); // Check every 5 seconds
}

function stopPerformanceMonitoring() {
  if (performanceMonitorInterval) {
    clearInterval(performanceMonitorInterval);
    performanceMonitorInterval = null;
  }
}

function saveIpSettings(project) {
  let saveLimit = document.getElementById("saveLimit").value;
  let autoBlockEnabled = document.getElementById("autoBlock").checked;
  let autoBlockThreshhold = document.getElementById("reputationThreshold").value;
  const ipSettings = {
    saveLimit: saveLimit,
    autoBlockEnabled: autoBlockEnabled,
    autoBlockThreshhold: autoBlockThreshhold
  };
  localStorage.setItem(`ips_${project}`, JSON.stringify(ipSettings))

  showFeedback('IPS settings saved successfully!');
}

document.getElementById("saveSettingsBtn").onclick = () => {
  if (!document.getElementById("saveLimit").value ||
    !document.getElementById("reputationThreshold").value
  ) { showFeedback("Fill out each field first") } else {
    saveIpSettings(currentlyEditingProject)
  }

};
// Tutorial check moved inside DOMContentLoaded

const saveCredentialsbtn = document.getElementById('saveCredentialsBtn');
saveCredentialsbtn.onclick = () => {
  if (saveCredentialsbtn.textContent === 'Save Credentials') {
    if (document.getElementById('projectId').value === '' || document.getElementById('projectPassword').value === '') {
      showFeedback('Please fill out both fields before saving.');
      return;
    }
    else {
      localStorage.setItem(`projectId_${currentlyEditingProject}`, document.getElementById('projectId').value);
      localStorage.setItem(`projectPassword_${currentlyEditingProject}`, document.getElementById('projectPassword').value);
      showFeedback('Credentials saved successfully!');
      document.getElementById('projectId').readOnly = true;
      document.getElementById('projectPassword').readOnly = true;
      saveCredentialsbtn.textContent = 'Edit Credentials';
    }
  }
  else {
    document.getElementById('projectId').readOnly = false;
    document.getElementById('projectPassword').readOnly = false;
    saveCredentialsbtn.textContent = 'Save Credentials';
  }
}

document.getElementById('connectSupabaseBtn').onclick = () => {
  if (document.getElementById('projectId').value === '' || document.getElementById('projectPassword').value === '' || document.getElementById("saveLimit").value === '' || document.getElementById("reputationThreshold").value === '') {
    showFeedback('Please fill out each supabase field.');
    return;
  } else {
    proxyPort = loadProxySettings(currentlyEditingProject).proxyPort;
    fetch(`http://localhost:${proxyPort}/api/supabase/connect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        projectId: document.getElementById('projectId').value,
        password: document.getElementById('projectPassword').value,
        saveLimit: parseInt(document.getElementById("saveLimit").value, 10),
        autoBlockEnabled: document.getElementById("autoBlock").checked,
        autoBlockThreshhold: parseInt(document.getElementById("reputationThreshold").value, 10)
      })

    })
      .then(response => response.text())
      .then(text => {
        showFeedback(text);
        if (text.includes('Successfully')) {
          document.getElementById('connStatus').textContent = 'Status: Connected';
          document.getElementById('connStatus').style.color = '#64ffda';
          localStorage.setItem(`supabaseConnected_${currentlyEditingProject}`, 'true');
        } else {
          document.getElementById('connStatus').textContent = 'Status: Not Connected';
          document.getElementById('connStatus').style.color = '#ff5757';
          localStorage.setItem(`supabaseConnected_${currentlyEditingProject}`, 'false');
        }
      })
      .catch(error => {
        showFeedback(`Error connecting to Supabase: ${error.message}`);
        document.getElementById('connStatus').textContent = 'Status: Not Connected';
        document.getElementById('connStatus').style.color = '#ff5757';
        localStorage.setItem(`supabaseConnected_${currentlyEditingProject}`, 'false')

      });
  }
}

document.getElementById('saveRedisSettingsBtn').onclick = () => {
  const redisHost = document.getElementById('redisHost').value;
  const redisPort = document.getElementById('redisPort').value;
  const redisPassword = document.getElementById('redisPassword').value;
  const redisUsername = document.getElementById('redisUsername').value;
  const redisDatabase = document.getElementById('redisDatabase').value || '0'

  if (!redisHost || !redisPort) {
    showFeedback('Please fill out required Redis fields.');
    return;
  }

  localStorage.setItem(`redisSettings_${currentlyEditingProject}`, JSON.stringify({
    host: redisHost,
    port: redisPort,
    password: redisPassword,
    username: redisUsername,
    database: redisDatabase,
    tls: document.getElementById('redisTLS').checked
  }));

  showFeedback('Redis settings saved successfully!');

}
