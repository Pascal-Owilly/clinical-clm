from django import template

register = template.Library()

@register.filter
def underscore_to_space(value):
    """
    Replaces underscores with spaces and capitalizes the first letter of each word.
    For example: "receptionist_admin" becomes "Receptionist Admin".
    """
    if isinstance(value, str):
        # Replace underscores with spaces, then title case each word
        return value.replace('_', ' ').title()
    return value

# You can keep other custom filters here if you have them, e.g., 'multiply'
@register.filter
def multiply(value, arg):
    try:
        return float(value) * float(arg)
    except (ValueError, TypeError):
        return ''

@register.filter(name='add_class')
def add_class(value, arg):
    """
    Adds a CSS class to a form field.
    """
    return value.as_widget(attrs={'class': arg})

@register.filter(name='add_attr')
def add_attr(field, css):
    """
    Adds attributes to a form field.
    Usage: {{ field|add_attr:"placeholder:Enter text,data-test:value" }}
    """
    attrs = {}
    pairs = css.split(',')
    for pair in pairs:
        key, value = pair.split(':')
        attrs[key.strip()] = value.strip()
    return field.as_widget(attrs=attrs)

@register.filter
def remove_page_param(querystring):
    """
    Removes the 'page' parameter from a query string.
    Useful for pagination links when other filters are present.
    """
    params = querystring.split('&')
    filtered_params = []
    for param in params:
        if not param.startswith('page='):
            filtered_params.append(param)
    return '&'.join(filtered_params)

@register.filter
def lrange(start, end):
    """
    Generates a list of numbers from start to end (inclusive).
    Useful for iterating through ranges in templates where built-in range isn't available.
    Usage: {% for i in 1|lrange:total_pages %}
    """
    return range(start, end + 1)