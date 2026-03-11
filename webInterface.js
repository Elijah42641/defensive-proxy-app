const express = require("express");
const { spawn } = require("child_process");
const path = require('path');

// Support multiple simultaneous proxies - key is project name, value is process info
const proxyProcesses = {};


const app = express();
const PORT = 1234;

// JSON + form parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "/")));


// Clean URLs
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

const fs = require("fs");

app.post('/api/project/get-current', (req, res) => {
      try {
        const data = { currentProject: data.projectName };
        if (endpoints) {
          data.endpoints = endpoints;
        }
        if (proxyEnabled !== null) {
          data.proxyEnabled = proxyEnabled;
        }
        fs.writeFileSync(currentProjectFile, JSON.stringify(data, null, 2), 'utf8');
        console.log('Successfully updated current_project.json with project:', projectName, 'endpoints count:', endpoints ? endpoints.length : 0, 'proxyEnabled:', proxyEnabled);
      } catch (error) {
        console.error('Error updating current_project.json:', error);
      }
    }
)

app.post("/api/project/update-current", (req, res) => {
  const { projectName } = req.body;

  if (!projectName) {
    return res.status(400).json({ error: "projectName is required" });
  }

  try {
    const filePath = path.join(__dirname, "public", "current_project.json");

    fs.writeFileSync(
      filePath,
      JSON.stringify(
        {
          currentProject: projectName,
          updatedAt: Date.now()
        },
        null,
        2
      ),
      "utf8"
    );

    res.json({ status: "ok", project: projectName });
  } catch (err) {
    console.error("Failed to update current project file:", err);
    res.status(500).json({ error: "Failed to update project file" });
  }
});


// add proxy APIs (enable proxy and stop proxy)

app.post("/api/proxy/enable", (req, res) => {
    try {
        const {
            projectPath,
            proxyPort,
            serverPort,
            currentProject
        } = req.body;

        // Validate required fields
        if (!currentProject) {
            return res.status(400).json({ error: "currentProject is required" });
        }
        if (!proxyPort || !serverPort) {
            return res.status(400).json({ error: "proxyPort and serverPort are required" });
        }

        // Check if this specific project already has a proxy running
        if (proxyProcesses[currentProject]) {
            try {
                process.kill(proxyProcesses[currentProject].pid, 0);
                return res.status(409).json({
                    error: `Proxy for project "${currentProject}" is already running on port ${proxyProcesses[currentProject].port}`
                });
            } catch (e) {
                // Process not running, clean up
                delete proxyProcesses[currentProject];
            }
        }

        // Check if the port is already in use by another proxy
        for (const [proj, procInfo] of Object.entries(proxyProcesses)) {
            if (procInfo.port === proxyPort) {
                return res.status(409).json({
                    error: `Port ${proxyPort} is already in use by proxy for project "${proj}"`
                });
            }
        }

        const proxyCwd = projectPath || path.join(__dirname, "application");

        // Start the proxy process
        const proxyProcess = spawn('/usr/local/go/bin/go', ['run', 'proxy.go'], {
            cwd: proxyCwd,
            env: {
                ...process.env,
                PROXY_PORT: proxyPort,
                SERVER_PORT: serverPort,
                CURRENT_PROJECT: currentProject
            }
        });

        // Track this proxy process
        proxyProcesses[currentProject] = {
            process: proxyProcess,
            pid: proxyProcess.pid,
            port: proxyPort,
            serverPort: serverPort,
            startTime: Date.now()
        };

        proxyProcess.stdout.on("data", (data) => {
            console.log(`Proxy [${currentProject}] stdout:`, data.toString());
        });

        proxyProcess.stderr.on("data", (data) => {
            console.log(`Proxy [${currentProject}] stderr:`, data.toString());
        });

        proxyProcess.on("close", (code) => {
            console.log(`Proxy [${currentProject}] process closed with code:`, code);
            delete proxyProcesses[currentProject];
        });

        proxyProcess.on("error", (err) => {
            console.error(`Proxy [${currentProject}] process error:`, err);
            delete proxyProcesses[currentProject];
        });

        res.json({
            status: "started",
            proxyPort,
            serverPort,
            currentProject,
            message: `Proxy started for project "${currentProject}" on port ${proxyPort}`
        });
    } catch (e) {
        console.error("Error starting proxy:", e);
        res.status(500).json({ error: "Failed to start proxy" });
    }
});

// Get status of all proxies
app.get("/api/proxy/status-all", (req, res) => {
    const status = {};
    for (const [project, info] of Object.entries(proxyProcesses)) {
        try {
            process.kill(info.pid, 0);
            status[project] = {
                running: true,
                port: info.port,
                serverPort: info.serverPort,
                uptime: Date.now() - info.startTime
            };
        } catch (e) {
            // Process not running
            delete proxyProcesses[project];
        }
    }
    res.json({ proxies: status, count: Object.keys(status).length });
});


function normalizeIP(ip) {
    // Handle IPv4-mapped IPv6 addresses like ::ffff:127.0.0.1
    if (ip.startsWith("::ffff:")) {
        return ip.slice(7);
    }

    return ip;
}




const ALLOWED_IPS = new Set([
    "127.0.0.1",
    "::1",
    "1.1.1.1"
]);

app.post("/api/stop-proxy", (req, res) => {
    const rawIP = req.ip;
    const ip = normalizeIP(rawIP);
    const { projectName } = req.body; // Optional: specify which project to stop

    console.log("Raw IP:", rawIP, "Normalized IP:", ip);

    if (!ALLOWED_IPS.has(ip)) {
        return res.status(403).json({ error: "Forbidden" });
    }

    // If no specific project is provided, stop all proxies
    if (!projectName) {
        const projects = Object.keys(proxyProcesses);
        if (projects.length === 0) {
            return res.status(400).json({
                error: "No proxy servers running"
            });
        }

        let stopped = [];
        let errors = [];
        
        for (const proj of projects) {
            try {
                if (proxyProcesses[proj]) {
                    process.kill(proxyProcesses[proj].pid, "SIGTERM");
                    stopped.push(proj);
                    delete proxyProcesses[proj];
                }
            } catch (e) {
                errors.push(proj);
                delete proxyProcesses[proj];
            }
        }

        res.json({
            status: "stopped",
            stoppedProjects: stopped,
            message: `Stopped ${stopped.length} proxy(ies)`
        });
        return;
    }

    // Stop a specific project's proxy
    if (!proxyProcesses[projectName]) {
        return res.status(400).json({
            error: `No proxy running for project "${projectName}"`
        });
    }

    try {
        process.kill(proxyProcesses[projectName].pid, "SIGTERM");
        delete proxyProcesses[projectName];

        res.json({
            status: "stopped",
            project: projectName,
            message: `Proxy for project "${projectName}" stopped`
        });
    } catch (e) {
        delete proxyProcesses[projectName];
        res.status(500).json({ error: `Failed to stop proxy for project "${projectName}"` });
    }
});



/* ---------------- START ---------------- */

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
