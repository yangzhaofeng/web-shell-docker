const express = require('express')
const app = express();
const expressWs = require('express-ws')(app);
const pty = require('node-pty');

app.use(express.static('static'));

app.ws('/shell', (ws, req) => {
  var shell;
  if (Number(process.env.nc_raw)) {
    shell = pty.spawn('/bin/bash', ['-c', 'stty raw -echo; ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p ' + process.env.nc_port + ' root@' + process.env.nc_host]);
  } else {
    shell = pty.spawn('/usr/bin/ssh', ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-p", process.env.nc_port, "root@" + process.env.nc_host]);
  }
  shell.on('data', (data) => {
    ws.send(data);
  });
  ws.on('message', (msg) => {
    shell.write(msg);
  });
  shell.on('close', () => {
    ws.close();
  });
  ws.on('close', () => {
    shell.kill();
  });
});

app.listen(3000);
