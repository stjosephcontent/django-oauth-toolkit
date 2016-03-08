from django.db import models
from oauth2_provider.models import AbstractApplication, AbstractOrganization


class TestApplication(AbstractApplication):
    custom_field = models.CharField(max_length=255)


class TestOrganization(AbstractOrganization):
    description = models.CharField(max_length=255)
