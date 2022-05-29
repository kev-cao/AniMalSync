from flask import request, url_for, redirect
from urllib.parse import urlparse, urljoin

def is_safe_url(target):
    """
    Checks that the target url matches the original site url.

    Args:
        target (str): The desired target URL

    Returns:
        (bool): True if the target matches the site url, False otherwise
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def get_redirect_target():
    """
    Fetches the redirect target from a request.

    Returns:
        (str|None): The redirect target if it exists, otherwise false
    """
    for target in request.values.get('next'), request.args.get('next'):
        if not target:
            continue
        elif is_safe_url(target):
            return target

def redirect_back(*, fallback, **values):
    """
    Redirects to the target URL in the request if it is safe, otherwise
    redirects to a fallback.

    Args:
        fallback (str): Fallback endpoint in case request URL is not safe
        values (dict): Query params
    """
    target = request.form['next'] if request.form \
        and 'next' in request.form else request.args.get('next')
    if not target or not is_safe_url(target):
        target = fallback
    return redirect(target)