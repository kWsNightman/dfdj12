from django import forms


class MyForm(forms.Form):
    name_0 = forms.CharField(max_length=50, label='Name', label_suffix='')


    def __init__(self,*args,**kwargs):
        super(MyForm, self).__init__(*args,**kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'
            field.widget.attrs['placeholder'] = 'Enter name'

