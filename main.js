// --- Element References ---
const projectsList = document.getElementById('projectsList');
const folderInput = document.getElementById('folderInput');
const endpointsList = document.getElementById('endpointsList');
const tabButtons = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');
const endpointsTab = document.getElementById('endpointsTab');
const proxyTab = document.getElementById('proxyTab');
const currentProjectDisplay = document.getElementById('currentProjectDisplay');
const exitEditModeBtn = document.getElementById('exitEditModeBtn');
const addEndpointBtn = document.getElementById('addEndpointBtn');
const newEndpointInput = document.getElementById('newEndpointInput');
const endpointControls = document.getElementById('endpointControls');
const whitelistInput = document.getElementById('whitelistInput');
const blacklistPatterns = document.getElementById('blacklistPatterns');
const saveEndpointSettingsBtn = document.getElementById('saveEndpointSettingsBtn');
const endpointSettingsSection = document.getElementById('endpointSettings'); // New reference for the settings section

// Feedback element
const feedbackDisplay = document.createElement('div');
feedbackDisplay.id = 'feedback-display';
feedbackDisplay.style.cssText = `
  background: #ffc107;
  color: #333;
  padding: 0.5rem;
  border-radius: 5px;
  margin-top: 1rem;
  display: none;
`;
document.getElementById('endpointControls').before(feedbackDisplay);


// --- Global State ---
let projectNames = [];
let sessionEndpoints = {};
let currentlyEditingProject = null;
let selectedEndpoint = null;


// --- Data Management Functions ---
function loadProjects() {
  try {
    const raw = localStorage.getItem('projects');
    projectNames = raw ? JSON.parse(raw) : [];
  } catch {
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

function loadProjectEndpoints(projectName) {
  try {
    const rawEndpoints = localStorage.getItem(`endpoints_${projectName}`);
    const endpoints = rawEndpoints ? JSON.parse(rawEndpoints) : [];
    sessionEndpoints[projectName] = { endpoints: endpoints };
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

function renderProjectsList() {
  projectsList.innerHTML = '';
  if (projectNames.length === 0) {
    projectsList.innerHTML = '<p>No projects added yet.</p>';
    return;
  }
  projectNames.forEach(name => {
    const card = document.createElement('div');
    card.className = 'project-card';
    card.innerHTML = `
      <h3>${name}</h3>
      <button class="small-btn enter-edit-btn" data-project="${name}">Enter Edit Mode</button>
    `;
    projectsList.appendChild(card);
  });
}

function renderEndpoints(projectName) {
  endpointsList.innerHTML = '';
  const eps = sessionEndpoints[projectName]?.endpoints || [];
  if (eps.length === 0) {
    endpointsList.innerHTML = '<li>No endpoints added yet.</li>';
    return;
  }
  eps.forEach((ep) => {
    const li = document.createElement('li');
    li.dataset.endpointPath = ep.path;
    
    // Create the content for the list item
    const endpointPathSpan = document.createElement('span');
    endpointPathSpan.textContent = ep.path;
    li.appendChild(endpointPathSpan);
    
    const buttonGroup = document.createElement('div');
    buttonGroup.className = 'endpoint-actions';

    const editBtn = document.createElement('button');
    editBtn.textContent = 'Edit';
    editBtn.className = 'small-btn edit-endpoint-btn';
    editBtn.onclick = (e) => {
      e.stopPropagation();
      // Find and select the endpoint
      selectedEndpoint = sessionEndpoints[projectName].endpoints.find(item => item.path === ep.path);
      
      // Update UI to reflect the selected endpoint
      document.querySelectorAll('.endpoints-list li').forEach(item => item.classList.remove('selected-endpoint'));
      li.classList.add('selected-endpoint');
      
      // Populate inputs with endpoint settings and show the settings section
      populateEndpointSettingsInputs(selectedEndpoint);
      endpointSettingsSection.style.display = 'block';
    };
    
    const delBtn = document.createElement('button');
    delBtn.textContent = 'X';
    delBtn.className = 'small-btn delete-endpoint-btn';
    delBtn.onclick = (e) => {
      e.stopPropagation();
      sessionEndpoints[projectName].endpoints = sessionEndpoints[projectName].endpoints.filter(item => item.path !== ep.path);
      saveProjectEndpoints(projectName);
      
      if (selectedEndpoint && selectedEndpoint.path === ep.path) {
        selectedEndpoint = null;
        clearEndpointSettingsInputs();
        endpointSettingsSection.style.display = 'none';
      }
      renderEndpoints(projectName);
    };
    
    buttonGroup.appendChild(editBtn);
    buttonGroup.appendChild(delBtn);
    li.appendChild(buttonGroup);
    endpointsList.appendChild(li);
  });
}

function switchTab(tabId) {
  tabButtons.forEach(b => b.classList.remove('active'));
  tabContents.forEach(t => t.classList.remove('active'));
  const newActiveBtn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
  newActiveBtn.classList.add('active');
  document.getElementById(tabId).classList.add('active');
}

function clearEndpointSettingsInputs() {
  whitelistInput.value = '';
  blacklistPatterns.value = '';
}

function populateEndpointSettingsInputs(endpoint) {
  whitelistInput.value = endpoint.whitelist ? endpoint.whitelist.join(', ') : '';
  blacklistPatterns.value = endpoint.blacklist ? endpoint.blacklist.join('\n') : '';
}


// --- Event Handlers ---
folderInput.addEventListener('change', (e) => {
  const files = Array.from(e.target.files || []);
  if (!files.length) return;
  const folderName = (files[0].webkitRelativePath || files[0].name).split('/')[0].trim();
  if (!folderName || projectNames.includes(folderName)) {
    showFeedback('Project with this name already exists or is invalid.');
    return;
  }
  projectNames.push(folderName);
  sessionEndpoints[folderName] = { endpoints: [] };
  saveProjects();
  renderProjectsList();
  folderInput.value = '';
});

projectsList.addEventListener('click', (e) => {
  if (e.target.classList.contains('enter-edit-btn')) {
    const projectName = e.target.dataset.project;
    currentlyEditingProject = projectName;
    
    endpointsTab.classList.remove('hidden');
    proxyTab.classList.remove('hidden');

    switchTab('endpoints');
    currentProjectDisplay.textContent = `Currently Editing Project: ${projectName}`;
    
    loadProjectEndpoints(projectName);
    renderEndpoints(projectName);
    endpointControls.style.display = 'block';
    endpointSettingsSection.style.display = 'none'; // Hide settings when entering edit mode
  }
});

addEndpointBtn.addEventListener('click', () => {
  const project = currentlyEditingProject;
  const endpointPath = newEndpointInput.value.trim();
  if (!project) return;
  
  if (!endpointPath) {
    showFeedback('Please enter an endpoint path.');
    newEndpointInput.value = '';
    newEndpointInput.focus();
    return;
  }

  if (!sessionEndpoints[project]) {
    sessionEndpoints[project] = { endpoints: [] };
  }
  
  const exists = sessionEndpoints[project].endpoints.some(ep => ep.path === endpointPath);
  
  if (!exists) {
    const newEndpoint = {
      path: endpointPath,
      whitelist: [],
      blacklist: []
    };
    sessionEndpoints[project].endpoints.push(newEndpoint);
    saveProjectEndpoints(project);
    renderEndpoints(project);
    newEndpointInput.value = '';
    showFeedback('Endpoint added successfully!');
  } else {
    showFeedback('This endpoint already exists.');
    newEndpointInput.value = '';
    newEndpointInput.focus();
  }
});

saveEndpointSettingsBtn.addEventListener('click', () => {
  if (!selectedEndpoint) {
    showFeedback('Please select an endpoint to save settings for.');
    return;
  }
  const project = currentlyEditingProject;
  const newWhitelist = whitelistInput.value.split(',').map(item => item.trim()).filter(item => item !== '');
  const newBlacklist = blacklistPatterns.value.split('\n').map(item => item.trim()).filter(item => item !== '');

  selectedEndpoint.whitelist = newWhitelist;
  selectedEndpoint.blacklist = newBlacklist;
  
  saveProjectEndpoints(project);
  showFeedback(`Settings saved for endpoint: ${selectedEndpoint.path}`);
});


exitEditModeBtn.addEventListener('click', () => {
  currentlyEditingProject = null;
  selectedEndpoint = null;
  clearEndpointSettingsInputs();
  endpointsTab.classList.add('hidden');
  proxyTab.classList.add('hidden');
  switchTab('projects');
  endpointsList.innerHTML = '<li>Select a project to see endpoints.</li>';
  currentProjectDisplay.textContent = 'Currently Editing Project: None';
  endpointControls.style.display = 'none';
  endpointSettingsSection.style.display = 'none';
});

tabButtons.forEach(btn => {
  if (btn.dataset.tab === 'projects') {
    btn.addEventListener('click', () => {
      switchTab('projects');
    });
  }
});

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
  loadProjects();
  projectNames.forEach(projectName => {
    loadProjectEndpoints(projectName);
  });
  renderProjectsList();
});