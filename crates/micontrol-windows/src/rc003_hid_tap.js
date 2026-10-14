// Adapted from Bob-Bo1/Vibe-Remote / remote-bridge-hub (GPL-3.0-only).
// Observe RC003 reports and strip its voice F5 before HidOverGatt translates it.
// A short authenticated app lease restores original reports on disconnect.
let endpointPath = null;
let connection = null;
let output = null;
let token = null;
let retry = null;
let writes = Promise.resolve();
let voiceGuardUntil = 0;
function resetConnection(current) {
  if (current === null || connection !== current) return;
  voiceGuardUntil = 0;
  output = null;
  connection = null;
  current.close().catch(() => {});
  reconnect();
}
async function readControls(current, sessionToken) {
  let pending = '';
  try {
    while (connection === current) {
      const chunk = new Uint8Array(await current.input.read(1024));
      if (chunk.length === 0) break;
      pending += Array.from(chunk, b => String.fromCharCode(b)).join('');
      if (pending.length > 4096) break;
      let newline;
      while ((newline = pending.indexOf('\n')) !== -1) {
        const message = JSON.parse(pending.slice(0, newline));
        pending = pending.slice(newline + 1);
        if (connection === current && message.token === sessionToken && message.kind === 'voice_guard') {
          voiceGuardUntil = Date.now() + 6000;
        }
      }
    }
  } catch (_) { /* EOF, invalid control, or connection closed */ }
  resetConnection(current);
}
function stripVoiceF5(bytes) {
  if (bytes.length !== 9 || bytes[0] !== 1 || bytes[1] !== 0 || bytes[2] !== 0) return false;
  let changed = false;
  for (let offset = 3; offset < 9; offset += 2) {
    if ((bytes[offset] | (bytes[offset + 1] << 8)) === 0x003e) {
      bytes[offset] = 0;
      bytes[offset + 1] = 0;
      changed = true;
    }
  }
  return changed;
}
function reconnect() {
  if (retry !== null) return;
  retry = setTimeout(() => { retry = null; connect(); }, 1000);
}
function emit(payload) {
  const current = output;
  const stream = connection;
  if (current === null) { reconnect(); return; }
  const text = JSON.stringify({ ...payload, token, pid: Process.id }) + '\n';
  const bytes = Array.from(text, c => c.charCodeAt(0) & 255);
  writes = writes.then(() => current.writeAll(bytes)).catch(() => {
    if (output === current) resetConnection(stream);
  });
}
async function connect() {
  if (output !== null || endpointPath === null) return;
  try {
    const endpoint = JSON.parse(File.readAllText(endpointPath));
    token = endpoint.token;
    connection = await Socket.connect({ family: 'ipv4', host: '127.0.0.1', port: endpoint.port });
    output = connection.output;
    readControls(connection, token);
    emit({ kind: 'ready', protocol: 3 });
  } catch (_) { output = null; connection = null; reconnect(); }
}
function hex(pointer, length) {
  return Array.from(new Uint8Array(pointer.readByteArray(length)),
    b => b.toString(16).padStart(2, '0')).join('');
}
rpc.exports = {
  async init(_stage, parameters) {
    endpointPath = parameters.endpoint;
    const target = Process.findModuleByName('ntdll.dll').findExportByName('NtDeviceIoControlFile');
    Interceptor.attach(target, {
      onEnter(args) {
        this.capture = args[5].toUInt32() === 0x80018483 && args[9].toUInt32() === 9;
        if (this.capture) this.buffer = args[8];
      },
      onLeave(status) {
        if (!this.capture || status.toUInt32() !== 0 || this.buffer.isNull()) return;
        try {
          const raw = hex(this.buffer, 9);
          const bytes = new Uint8Array(this.buffer.readByteArray(9));
          const voiceFiltered = Date.now() < voiceGuardUntil && stripVoiceF5(bytes);
          if (voiceFiltered) this.buffer.writeByteArray(bytes.buffer);
          emit({ kind: 'gatt_read', raw, voiceFiltered });
        }
        catch (e) { emit({ kind: 'error', message: String(e) }); }
      }
    });
    setInterval(() => { if (output === null) reconnect(); else emit({ kind: 'heartbeat', protocol: 3 }); }, 3000);
    await connect();
  }
};
