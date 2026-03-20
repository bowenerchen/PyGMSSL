"""Custom exceptions for the gmssl library."""


class GmSSLError(Exception):
    """Base exception for all gmssl errors."""


class InvalidSignature(GmSSLError):
    """Raised when a cryptographic signature verification fails."""


class InvalidTag(GmSSLError):
    """Raised when an AEAD tag verification fails."""


class InvalidKey(GmSSLError):
    """Raised when a key is malformed or invalid."""


class InvalidParameter(GmSSLError):
    """Raised when a parameter value is out of range or invalid."""


class AlreadyFinalized(GmSSLError):
    """Raised when an operation is attempted on an already-finalized context."""


class NotYetFinalized(GmSSLError):
    """Raised when a result is requested before finalization."""


class UnsupportedAlgorithm(GmSSLError):
    """Raised when an unsupported algorithm is requested."""
