from django import forms
from .models import Vendor


class VendorForm(forms.ModelForm):
    class meta:
        model = Vendor
        fields = ['vendor_name', 'vendor_license']