function checkCookie() {
    let temporary_session = {
        %s
    }
    if(temporary_session.temporary_session !== undefined) {
        %s
        getSessionByTemporaryToken(temporary_session);
    }
    if(getCookie("%s")){
        window.location.reload()
    }
}