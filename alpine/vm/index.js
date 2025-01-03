//
//
const express = require('express');
const { VM } = require('vm2');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const port = 3000;

app.use(bodyParser.json());

// Serve static HTML files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'index.html'));
});

app.get('/limitations', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'limitations.html'));
});

app.get('/about', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'about.html'));
});

app.get('/editor', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'editor.html'));
});

// Endpoint to run user-submitted code
app.post('/run', (req, res) => {
    const code = Buffer.from(req.body.code, 'base64').toString('utf-8');
    const output = [];

    const vm = new VM({
        timeout: 5000,
        console: 'redirect',
        sandbox: {
            console: {
                log: (...args) => {
                    output.push(args.map(String).join(' '));
                },
            },
            require: (moduleName) => {
                const disallowedModules = ['child_process', 'fs'];
                if (disallowedModules.includes(moduleName)) {
                    throw new Error(`Module "${moduleName}" is not allowed`);
                }
                return require(moduleName);
            }
        },
    });

    try {
        const result = vm.run(code);
        output.push(result);
        res.json({ output: output.join('\r\n') });
    } catch (error) {
        const errorMessage = error.message.split('\n')[0];
        res.json({ error: errorMessage });
    }
});

// Start the server
app.listen(port, () => {
    console.log(`App listening at http://127.0.0.1:${port}`);
});

//
// package.json
//

{
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js"
  },
  "dependencies": {
    "body-parser": "^1.20.2",
    "express": "^4.18.2",
    "package.json": "^0.0.0",
    "vm2": "^3.9.xx"
  },
  "devDependencies": {
    "nodemon": "^2.0.22"
  }
}

//
//
