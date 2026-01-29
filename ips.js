function saveIpSettings(project) {
  let saveLimit = document.getElementById("saveLimit").value;
  let autoBlockThreshhold = document.getElementById("reputationThreshold").value;
  let autoBlockTime = document.getElementById("timeToBlockIP").value
  const ipSettings = {
    saveLimit: saveLimit,
    autoBlockThreshhold: autoBlockThreshhold,
    autoBlockTime: autoBlockTime
  };
  localStorage.setItem(`ips_${project}`, JSON.stringify(ipSettings))

  showFeedback('IPS settings saved successfully!');
}

document.getElementById("saveSettingsBtn").onclick = () => {
  if (!document.getElementById("saveLimit").value ||
    !document.getElementById("reputationThreshold").value ||
    !document.getElementById("timeToBlockIP").value
  ) { showFeedback("Fill out each field first");  } else {
    saveIpSettings(currentlyEditingProject)
  }

};




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

document.getElementById('connectToRedisBtn').onclick = () => {
  const proxyPort = loadProxySettings(currentlyEditingProject).proxyPort;
  let redisSettings = {};

  // Safe JSON parse
  try {
    const stored = localStorage.getItem(`redisSettings_${currentlyEditingProject}`);
    if (stored) redisSettings = JSON.parse(stored);
  } catch (e) {
    console.warn("Failed to parse Redis settings from localStorage, using defaults", e);
    redisSettings = {};
  }

  // Ensure correct types
  const redisHost = String(redisSettings.host || 'localhost');
  const redisPort = Number(redisSettings.port) || 6379;
  const redisPassword = String(redisSettings.password || '');
  const redisUsername = String(redisSettings.username || '');
  const redisDatabase = Number(redisSettings.database) || 0;
  const redisTLS = Boolean(redisSettings.tls) || false;

  console.log(`redis host: ${redisHost}, port: ${redisPort}, username: ${redisUsername}, database: ${redisDatabase}, tls: ${redisTLS}`);

  // Validate required fields
  if (!redisHost || !redisPort) {
    showFeedback('Please fill out required Redis fields and save settings before connecting.');
    return;
  }

  // Send properly typed JSON to backend
  fetch(`http://localhost:${proxyPort}/api/redis/connect`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      host: redisHost,
      port: redisPort,
      password: redisPassword,
      username: redisUsername,
      database: redisDatabase,
      tls: redisTLS,
      saveLimit: parseInt(document.getElementById("saveLimit").value, 10),
      autoBlockThreshhold: parseInt(document.getElementById("reputationThreshold").value, 10),
      timeToBlock: parseInt(document.getElementById("timeToBlockIP").value, 10)
    })
  })
    .then(response => response.text())
    .then(text => {
      showFeedback(text);
      const statusElem =  document.getElementById('redisStatus');
      if (text.includes('Successfully')) {
        statusElem.textContent = 'Status: Connected';
        statusElem.style.color = '#64ffda';
        localStorage.setItem(`redisConnected_${currentlyEditingProject}`, 'true');
      } else {
        statusElem.textContent = 'Status: Not Connected';
        statusElem.style.color = '#ff5757';
        localStorage.setItem(`redisConnected_${currentlyEditingProject}`, 'false');
      }
    })
    .catch(err => {
      console.error("Redis connection failed:", err);
      showFeedback("Redis connection failed: " + err.message);
    });
}
