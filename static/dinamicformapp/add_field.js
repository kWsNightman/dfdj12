let id = 1

function addField() {
    let a = $('.form-group')
    let par = document.createElement('p')
    let label = document.createElement('label')
    let input = document.createElement('input')

    input.name = 'name_' + id;
    input.id = 'id_name_' + id;
    input.className = 'form-control';
    input.type = 'text';
    input.maxLength = 50;
    input.placeholder = 'Enter name'
    input.required = true

    label.setAttribute("for", "id_name_" + id);
    label.innerText = 'Name ' + id;

    par.append(label, input)
    a.append(par)
    id ++
}