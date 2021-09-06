from django.shortcuts import render


def index(request):
    return render(request, 'dfdj12/base.html')
