// Save this as updateCurrentProject.js in your Electron app
const fs = require('fs');
const path = require('path');
const publicDir = path.join(__dirname, 'public');
const currentProjectFile = path.join(publicDir, 'current_project.json');

function updateCurrentProjectFile(projectName, endpoints = null, proxyEnabled = null) {
  try {
    const data = { currentProject: projectName };
    if (endpoints) {
      data.endpoints = endpoints;
    }
    // NOTE: proxyEnabled is NO LONGER saved to the JSON file.
    // It's now tracked per-project in localStorage (proxySettings_{projectName})
    // This prevents the issue where enabling proxy for one project affects all projects.
    
    fs.writeFileSync(currentProjectFile, JSON.stringify(data, null, 2), 'utf8');
    console.log('Successfully updated current_project.json with project:', projectName, 'endpoints count:', endpoints ? endpoints.length : 0);
  } catch (error) {
    console.error('Error updating current_project.json:', error);
  }
}

// Example usage: call this whenever the user switches projects
// updateCurrentProjectFile('YourProjectName');

module.exports = { updateCurrentProjectFile };
