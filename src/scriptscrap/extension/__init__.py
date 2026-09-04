"""Optional Firefox WebExtension forensic sensor.

Loaded into Camoufox only in forensic mode. Normal capture never touches this
package, and the investigator works without it.

See `README.md` in this directory for what the extension observes and why each
observation needs an extension rather than Playwright or page JavaScript.
"""

from .loader import build_extension, cleanup_extension
from .transport import ExtensionTransport

__all__ = ["ExtensionTransport", "build_extension", "cleanup_extension"]
