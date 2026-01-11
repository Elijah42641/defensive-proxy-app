const express = require("express");
const { spawn } = require("child_process");
const path = require('path');

let proxyProcess = null;


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

        // Check if proxy already running
        if (proxyProcess) {
            try {
                process.kill(proxyProcess.pid, 0);
                return res.status(409).json({
                    error: "Proxy server is already running"
                });
            } catch (e) {
                console.log(e);
                proxyProcess = null;
            }
        }

        const proxyCwd =
            projectPath || path.join(__dirname, "application");

        // Validate required fields
        if (!currentProject) {
            return res.status(400).json({ error: "currentProject is required" });
        }
        if (!proxyPort || !serverPort) {
            return res.status(400).json({ error: "proxyPort and serverPort are required" });
        }

        proxyProcess = proxyProcess = spawn('/usr/local/go/bin/go', ['run', 'proxy.go'], {
            cwd: proxyCwd,
            env: {
                ...process.env,
                PROXY_PORT: proxyPort,
                SERVER_PORT: serverPort,
                CURRENT_PROJECT: currentProject
            }
        });

        proxyProcess.stdout.on("data", (data) => {
            console.log("Proxy stdout:", data.toString());
        });

        proxyProcess.stderr.on("data", (data) => {
            console.log("Proxy stderr:", data.toString());
        });

        proxyProcess.on("close", (code) => {
            console.log("Proxy process closed with code:", code);
            proxyProcess = null;
        });

        proxyProcess.on("error", (err) => {
            console.error("Proxy process error:", err);
            proxyProcess = null;
        });

        res.json({
            status: "started",
            proxyPort,
            serverPort,
            currentProject
        });
    } catch (e) {
        console.error("Error starting proxy:", e);
        res.status(500).json({ error: "Failed to start proxy" });
    }
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

    console.log("Raw IP:", rawIP, "Normalized IP:", ip);

    if (!ALLOWED_IPS.has(ip)) {
        return res.status(403).json({ error: "Forbidden" });
    }

    if (!proxyProcess) {
        return res.status(400).json({
            error: "No proxy server running"
        });
    }

    try {
        process.kill(proxyProcess.pid, "SIGTERM");
        proxyProcess = null;

        res.json({
            status: "stopped"
        });
    } catch (e) {
        proxyProcess = null;
        res.status(500).json({ error: "Failed to stop proxy" });
    }
});



/* ---------------- START ---------------- */

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
