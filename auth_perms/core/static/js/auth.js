if ('%(standalone)s' !== 'True') {
    // sending a connect request to the server.
    socket = io.connect('%(backend_domain)s', {
        path: '%(socket_path)s'
    })
    // Get session by temporary session
    function getSessionByTemporaryToken(temporary_session) {
        socket.emit('authorization', temporary_session);
    }
    // Send qr token in socket
    function emitQRToken(data) {
        socket.emit('authorization', data);
    }
    checkCookie();
}

//Sign in form behavior
const signInEmailInput = document.getElementById('inputEmailSignIn')
const signInPasswordInput = document.getElementById('inputPassword')
const signInBtn = document.getElementById('btnSignInForm')

const checkSignInInputs = () => signInBtn.disabled = signInEmailInput.value.length === 0 || signInPasswordInput.value.length === 0;

signInEmailInput.oninput = () => checkSignInInputs();
signInPasswordInput.oninput = () => checkSignInInputs();

checkSignInInputs();

//Sign up form behavior
const firstNameSignUpInput = document.getElementById('inputFirstName')
const lastNameSignUpInput = document.getElementById('inputSurname')
const emailSignUpInput = document.getElementById('inputEmailSignUp')
const passwordSignUpInput = document.getElementById('inputPasswordSignUp')
const confirmPasswordSignUpInput = document.getElementById('inputPasswordSignUpConfirm')
const signUpBtn = document.getElementById('btnSignUpForm')

const checkSignUpInputs = () => {
    signUpBtn.disabled = firstNameSignUpInput.value.length === 0 ||
        lastNameSignUpInput.value.length === 0 ||
        emailSignUpInput.value.length === 0 ||
        passwordSignUpInput.value.length === 0 ||
        passwordSignUpInput.value.length === 0 ||
        confirmPasswordSignUpInput.value.length === 0
}

firstNameSignUpInput.oninput = () => checkSignUpInputs();
lastNameSignUpInput.oninput = () => checkSignUpInputs();
emailSignUpInput.oninput = () => checkSignUpInputs();
passwordSignUpInput.oninput = () => checkSignUpInputs();
confirmPasswordSignUpInput.oninput = () => checkSignUpInputs();

checkSignUpInputs();

// Set cookie
function setCookie(name, value, days) {
    let expires = "";
    if (days) {
        let date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + (value || "") + expires + "; path=/";
}

// Function for getting value from cookie
function getCookie(cookie_name) {
    let name = cookie_name + "=";
    let decodedCookie = decodeURIComponent(document.cookie);
    let ca = decodedCookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) === 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

// Delete temporary session from cookie
function deleteCookie(cookie_name) {
    document.cookie = cookie_name + '=; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
}

// Default redirect function
function afterSaveSession(response) {
    window.location.replace('/')
}

var classic_login = document.getElementById("btnSignInForm");
var sso_login = document.getElementById("btnSignOnForm");

signInBtn.onclick = make_classic_login;

// Remove elements for standalone mode
if ('%(standalone)s' == 'True') {
    document.getElementById('SignOn').remove()
    let blocks = ['tabSignInQRInner', 'tabSignUpQRInner', 'tabSignInFormInner',
        'tabSignUpFormInner', 'collapseBtnHelp', 'ServicesDropdown']
    blocks.forEach(function (value) {
        document.getElementById(value).parentElement.remove()
        })
    }
else {
    sso_login.onclick = make_sso_login
}

function generateQr(data, elementId){
    var qr2 = new VanillaQR({
        url: data,
        width: 600,
        height: 600,
        colorLight: "#ffffff",
        colorDark: "#000000"
    });

    var imageElement = qr2.toImage("png");
    if (imageElement) {
        qr_html = document.getElementById(elementId)
        qr_html.innerHTML = ''
        qr_html.appendChild(imageElement)
    }

}

signUpBtn.onclick = function () {
    var data = {
        "uinfo": {
            "first_name": document.getElementById("inputFirstName").value,
            "last_name": document.getElementById("inputSurname").value
        },
        "email": document.getElementById("inputEmailSignUp").value,
        "password": document.getElementById("inputPasswordSignUp").value,
        "password_confirmation": document.getElementById("inputPasswordSignUpConfirm").value,
        "actor_type": "classic_user"
    }
    classic_registration(data);
    return false;
};

function classic_registration(data) {
    fetch(
        '%(registration_url)s',
        {
            method: "post",
            headers: {
                "Accept": "application / json",
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        }
    )
    .then(response => {
        if (response.ok) {
            document.getElementById("formSignUp").reset();
            window.location.reload();
        } else {
            response.json().then((response) => {
                Toast.fire({
                    icon: "error",
                    title: response["error_message"]
                })
            })
        }
    })
}

const Toast = Swal.mixin({
    toast: true,
    position: 'top-right',
    showConfirmButton: false,
    timer: 3000,
    timerProgressBar: true,
    didOpen: (toast) => {
        toast.addEventListener('mouseenter', Swal.stopTimer)
        toast.addEventListener('mouseleave', Swal.resumeTimer)
    }
})
