from django import forms
from .models import get_organization_model


class AllowForm(forms.Form):
    allow = forms.BooleanField(required=False)
    redirect_uri = forms.CharField(widget=forms.HiddenInput())
    scope = forms.CharField(widget=forms.HiddenInput())
    client_id = forms.CharField(widget=forms.HiddenInput())
    state = forms.CharField(required=False, widget=forms.HiddenInput())
    response_type = forms.CharField(widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        data = kwargs.get('data')
        # backwards compatible support for plural `scopes` query parameter
        if data and 'scopes' in data:
            data['scope'] = data['scopes']
        super(AllowForm, self).__init__(*args, **kwargs)


class AllowFormOrg(AllowForm):

    organization_id = forms.ChoiceField(required=True, choices=((None, 'None'),))

    def __init__(self, *args, **kwargs):
        organization_choices = kwargs.pop('organization_choices', (None, 'None'))
        super(AllowFormOrg, self).__init__(*args, **kwargs)
        try:
            # Since we're allowing to overwrite `organization_choices`, should check
            # if `choices` have correct format
            if not(all([len(x) == 2 for x in organization_choices])):
                raise ValueError("Invalid choices format provided.")
        except TypeError:
            raise ValueError('Invalid choices provided.')
        if hasattr(organization_choices, '__iter__'): # must be iterable
            self.fields['organization_id'].choices = organization_choices
        initial_organization = kwargs.get('initial', {}).get('organization_id', None)
        if initial_organization is not None:
            self.fields['organization_id'].widget.attrs['disabled'] = True

    @classmethod
    def get_extra_form_kwargs(cls, kwargs, view):
        """
        This class method is a hookup for the view to be able to swap forms without swapping
        Views. This is convenient when user wants to customize the form and provide extra
        functionality without a need to overwrite the View.

        Note: Deleting keys from kwargs will have no effect! Generally you don't want to
        change anything in initial kwargs, but it's still allowed.

        Note: It sould stay a class (or static) method, since it is used before initializing the form.

        :param kwargs: Default kwargs, provided for the Form
        :param view: The View that uses this form
        :return: kwargs
        """
        kwargs['organization_choices'] = get_organization_model().objects.values_list('pk', 'name')
        return kwargs
