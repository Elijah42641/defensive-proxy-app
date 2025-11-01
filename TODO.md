# TODO: Add Blocked IPs Monitoring Tab

## Backend Changes (proxy.go)
- [x] Add global map to track blocked IPs with timestamps
- [x] Modify checkRequestRules to record blocked IPs
- [x] Add /api/blocked-ips API endpoint to return blocked IPs as JSON

## Frontend Changes (main.js)
- [x] Add "Blocked IPs" tab button
- [x] Add tab content div with list and refresh button
- [x] Implement fetchBlockedIPs function
- [x] Add auto-refresh logic (every 10 seconds)
- [x] Update switchTab to handle new tab

## Testing
- [ ] Test blocking requests and verify IPs appear in tab
- [ ] Test refresh functionality
