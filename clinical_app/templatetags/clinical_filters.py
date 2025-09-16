# clinical/templatetags/clinical_filters.py
from django import template
import json

register = template.Library()

@register.filter(name='json_pretty')
def json_pretty(value):
    try:
        return json.dumps(json.loads(value), indent=2)
    except (TypeError, json.JSONDecodeError):
        return value # Return original value if it's not valid JSON

@register.filter
def replace(value, arg):
    """
    Replaces all occurrences of a substring with another string.
    Usage: {{ value|replace:"old,new" }}
    """
    if not isinstance(value, str):
        return value
    if ',' not in arg:
        return value.replace(arg, '') # If only one arg, remove it
    
    old, new = arg.split(',', 1)
    return value.replace(old, new)