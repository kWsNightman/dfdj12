from django.shortcuts import render, redirect
from django.urls import reverse

from dinamicformapp.forms import MyForm
from django.http import HttpResponseRedirect
import json

from dinamicformapp.models import FormModel


def form(request):
    result = {}
    if request.method == 'POST':
        forms = MyForm(request.POST)
        if forms.is_valid():
            for name, data in forms.data.items():
                if name.startswith('name') and data:
                    result[name] = data
            data = json.dumps(result)
            FormModel.objects.create(data=data)
            return HttpResponseRedirect(reverse('dinamicform:completed'))
    else:
        forms = MyForm()
    return render(request, 'dinamicformapp/dinamicform.html', {'form': forms})


def completed(request):
    data = FormModel.objects.all()
    return render(request, 'dinamicformapp/completed.html', {'data': data})
