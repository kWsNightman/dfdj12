function make_sso_login() {
    let data = {
        uuids: [],
        sessions: [],
        services: [],
        redirect_url: "%s/"
    };
    fetch( "%s/auth_authorization/" )
        .then(response => {
            response.json().then((response) => {
                data.uuids.push(response.uuid);
                data.sessions.push(response.session);
                document.cookie = "temporary_session=" + response["session"] + "; path=/";
                %s
            });
        });
        return false;
    };