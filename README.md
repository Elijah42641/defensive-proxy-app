
<h1> LOOKING FOR COLLABORATION </h1>


Blocks requests based on absolute values and regex <br>
in either the body, headers, or cookies <br><br>
Current objective: <br>
Make the request analyzer as <strong>STRONG</strong> as possible
<br>
<h2>Cool Features</h2>

<ul>
  <li>
    Blocks IPs for a configurable amount of time after they are blocked a
    configurable number of times
  </li>

  <li>
    Recommends security rules based on endpoint paths
    (auth, file upload, etc.)
  </li>

  <li>
    HTTP request analyzer – feed in a sample request to receive:
    <ul>
      <li>Recommended security rules</li>
      <li>Business logic advice (e.g. validate certain fields server-side only)</li>
    </ul>
  </li>

  <li>
    Built-in security rule guide for beginners
  </li>
</ul>
<br><br>

  <pre>
git clone https://github.com/Elijah42641/defensive-proxy-app
cd defensive-proxy-app
npm install
npm start
  </pre>
  For daemon:
  <pre>
    git clone https://github.com/Elijah42641/defensive-proxy-app
cd defensive-proxy-app
    node webInterface.js
  </pre>
  
If you see any bugs let me know I just added this and it might still be buggy

  <h2>Use cases:</h2>
  <ul>
    <li>.apis</li>
    <li>.authentication (block basic hacking techniques)</li>
    <li>.hacking tools that use certain headers</li>
    <li>.anything known to return robust responses</li>
    <li>.against known malicious headers</li>
    <li>.prevent code injection (sqli, xss, ssti, etc)</li>
  </ul>

  <h2>Ways to test proxy</h2>
  <p>Create test node server and set that as the server port, then run curl commands on proxy port. You can test headers, cookies, etc.</p>
  <p>Report any bugs through pull requesting read me and adding to the bugs list.</p>
  <br>
    <br>
      <br>
        <h2> New feature coming: </h2>
        <br>
<p>Learning Mode: This mode observes incoming traffic and uses a request analyzer to recommend custom blocking rules. It tracks details like field/header lengths, types, and how many fields/headers are in each request. Based on this data, it learns how to block requests by analyzing how dynamic or strict the fields are.</p>

Learning mode: learns based on field/headed lengths, field/header types, amount of fields/headers. Blocks based on how dynamic/strict the fields are</p>
  <h2>Bugs:</h2>
  

  <h2>If you see this share my repo to at least one person to help get some attention to my project.</h2>
