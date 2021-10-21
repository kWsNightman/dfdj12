document.getElementById("updateSignInQR").onclick = function () {
    url = new URL("%s");
    params = {'qr_type': 'authentication'}
    Object.keys(params).forEach(key => url.searchParams.append(key, params[key]))
    fetch(url)
    .then(function(response){
        response.json()
        .then(
            function(data) {
                emitQRToken(data)
                generateQr(JSON.stringify(data), "qrLogin")
            }
        )
    })
    return false;
}

document.getElementById("updateSignUpQR").onclick = function () {
    url = new URL("%s");
    params = { 'qr_type': 'registration' }
    Object.keys(params).forEach(key => url.searchParams.append(key, params[key]))
    fetch(url)
        .then(function (response) {
            response.json()
                .then(
                    function (data) {
                        generateQr(JSON.stringify(data), "qrRegistration")
                    }
                )
        })
    return false;
}

emitQRToken(%s);
emitQRToken(%s);
generateQr("%s", "qrLogin")
generateQr("%s", "qrRegistration")