"""PICKLE VAULT :: the locked room (World Of B0t challenge 14).

The flag only ever exists as this module-level constant. It is read from the
environment at boot, so nothing is baked into an image layer, and this file is
chmod 0400 in the Dockerfile so that reading it from disk is not a path either.
Anything that wants the flag has to get the running interpreter to hand it over.
"""

import os

# Injected at runtime. The literal is a placeholder so the module still imports
# outside the launcher.
VAULT_FLAG = os.environ.get("W0B_FLAG", "hex4b0t{REPLACED_AT_RUNTIME}")
