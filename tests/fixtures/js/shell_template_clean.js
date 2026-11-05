// Safe: only server-side values interpolated; and execFile with an
// argument array (no shell).
const backup = `tar czf /tmp/backup.tgz ${__dirname}/data`;
exec(backup);  // safe: Command Injection
const args = ["-i", inputPath, "-af", `asetrate=44100*${pitch}`];
execFile("ffmpeg", args, (err) => {});  // safe: Command Injection
