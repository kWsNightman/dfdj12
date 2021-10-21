fetch(
    "%s/save_session/",
    {
        method: "post",
        headers: {
            "Accept": "application/json",
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            session_token: data.%ssession_token
        })
    }
).then(
    function (response) {
        document.cookie = "%s=" + data.%ssession_token + "; path=/"
        %s
    }
)