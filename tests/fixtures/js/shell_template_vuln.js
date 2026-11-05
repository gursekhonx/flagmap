// Fixture for shell_template_guard.py (v1.59.0). Mirrors UofTCTF 2024
// "Voice Changer": the command is built on one line, exec()'d on the next.
fstream.on('close', function () {
  const command = `ffmpeg -i "${__dirname + '/upload/' + fileName}" -y -af "asetrate=44100*${formData.pitch}" out.ogg`;
  exec(command, (error, stdout, stderr) => {  // ruleid: Command Injection
    res.send(stdout);
  });
});
