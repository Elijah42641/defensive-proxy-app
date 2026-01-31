
<h1> LOOKING FOR COLLABORATION </h1>


Blocks requests based on absolute values and regex <br>
in either the body, headers, or cookies <br>
<br>
Cool features: <br>
.Can block ips for a custom time after they've been blocked a custom amount of times <br>
.Recommends rules based on endpoint path (auth,file, etc) <br>
.Http request analyzer: analyzes request and recommends rules or provides business logic advice eg: validate certain field server side only <br>
.Rule guide for security beginners <br>

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

  <h2>Bugs:</h2>
  

  <h2>If you see this share my repo to at least one person to help get some attention to my project.</h2>
