from django.db import models
from django.db.models import JSONField


# Create your models here.

class FormModel(models.Model):
    data = JSONField()

    def __str__(self):
        return f'Json id: {str(self.id)}'
