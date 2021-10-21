socket.on('authorization response', function (msg) {
    if (msg["session_token"] !== undefined) {
        %s
        saveSession(msg);
    }
});