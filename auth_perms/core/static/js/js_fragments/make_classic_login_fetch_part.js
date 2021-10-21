fetch(
    "%s/auth/",
    {
        method: "post",
        headers: {
            "Accept": "application/json",
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        if (response.ok) {
            response.json().then((response) => {
                document.cookie = "%s=" + response["session_token"] + "; path=/";
                %s
            })
        } else {
            response.json().then((response) => {
                Toast.fire({
                    icon: "error",
                    title: response["error_message"]
                })
            })
        }
    })
