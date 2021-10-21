function make_classic_login() {
    let data = {
        email: document.getElementById("inputEmailSignIn").value,
        password: document.getElementById("inputPassword").value,
        actor_type: "classic_user"
    };
    %s
    return false;
};