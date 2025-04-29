from django.shortcuts import redirect

class Redirect127ToLocalhostMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.get_host()
        if host.startswith("127.0.0.1"):
            # Rebuild the current URL with localhost instead of 127.0.0.1
            new_url = request.build_absolute_uri().replace("127.0.0.1", "localhost")
            return redirect(new_url)
        return self.get_response(request)
