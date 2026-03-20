"""
SM2 elliptic curve field arithmetic – Jacobian coordinates with gmpy2.

Reference: GM/T 0003-2012
"""

import gmpy2
from gmpy2 import mpz

# SM2 curve parameters (GM/T 0003-2012)
SM2_P = mpz(0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF)
SM2_A = mpz(0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC)
SM2_B = mpz(0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93)
SM2_N = mpz(0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123)
SM2_GX = mpz(0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7)
SM2_GY = mpz(0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0)


class JacobianPoint:
    """Point on SM2 curve in Jacobian coordinates (X, Y, Z).
    Affine (x, y) = (X/Z^2, Y/Z^3)
    """

    __slots__ = ('X', 'Y', 'Z')

    def __init__(self, X, Y, Z):
        self.X = mpz(X)
        self.Y = mpz(Y)
        self.Z = mpz(Z)

    @staticmethod
    def infinity():
        return JacobianPoint(mpz(1), mpz(1), mpz(0))

    @staticmethod
    def from_affine(x, y):
        return JacobianPoint(mpz(x), mpz(y), mpz(1))

    def is_infinity(self):
        return self.Z == 0

    def to_affine(self):
        """Convert to affine coordinates (x, y) as (mpz, mpz)."""
        if self.is_infinity():
            raise ValueError("Point at infinity has no affine coordinates")
        z_inv = gmpy2.invert(self.Z, SM2_P)
        z_inv2 = (z_inv * z_inv) % SM2_P
        z_inv3 = (z_inv2 * z_inv) % SM2_P
        x = (self.X * z_inv2) % SM2_P
        y = (self.Y * z_inv3) % SM2_P
        return (x, y)


def point_double(P):
    """Double a Jacobian point."""
    if P.is_infinity():
        return JacobianPoint.infinity()
    X1, Y1, Z1 = P.X, P.Y, P.Z
    A = (Y1 * Y1) % SM2_P
    B = (X1 * A * 4) % SM2_P
    C = (A * A * 8) % SM2_P
    D = (X1 * X1 * 3 + SM2_A * pow(Z1, 4, SM2_P)) % SM2_P
    X3 = (D * D - 2 * B) % SM2_P
    Y3 = (D * (B - X3) - C) % SM2_P
    Z3 = (2 * Y1 * Z1) % SM2_P
    return JacobianPoint(X3, Y3, Z3)


def point_add(P, Q):
    """Add two Jacobian points."""
    if P.is_infinity():
        return Q
    if Q.is_infinity():
        return P

    X1, Y1, Z1 = P.X, P.Y, P.Z
    X2, Y2, Z2 = Q.X, Q.Y, Q.Z

    Z1_sq = (Z1 * Z1) % SM2_P
    Z2_sq = (Z2 * Z2) % SM2_P
    U1 = (X1 * Z2_sq) % SM2_P
    U2 = (X2 * Z1_sq) % SM2_P
    S1 = (Y1 * Z2_sq % SM2_P * Z2) % SM2_P
    S2 = (Y2 * Z1_sq % SM2_P * Z1) % SM2_P

    H = (U2 - U1) % SM2_P
    R = (S2 - S1) % SM2_P

    if H == 0:
        if R == 0:
            return point_double(P)
        return JacobianPoint.infinity()

    H2 = (H * H) % SM2_P
    H3 = (H * H2) % SM2_P
    X3 = (R * R - H3 - 2 * U1 * H2) % SM2_P
    Y3 = (R * (U1 * H2 - X3) - S1 * H3) % SM2_P
    Z3 = (H * Z1 * Z2) % SM2_P
    return JacobianPoint(X3, Y3, Z3)


def scalar_multiply(k, P):
    """Compute k*P using double-and-add."""
    k = mpz(k) % SM2_N
    R = JacobianPoint.infinity()
    Q = P
    while k > 0:
        if k & 1:
            R = point_add(R, Q)
        Q = point_double(Q)
        k >>= 1
    return R


SM2_G = JacobianPoint.from_affine(SM2_GX, SM2_GY)


def point_to_bytes(x, y, compressed=False):
    """Encode affine point as bytes (uncompressed: 04 || x || y)."""
    xb = int(x).to_bytes(32, 'big')
    yb = int(y).to_bytes(32, 'big')
    if compressed:
        prefix = b'\x03' if int(y) & 1 else b'\x02'
        return prefix + xb
    return b'\x04' + xb + yb


def is_on_curve(x, y):
    """Check whether affine point (x, y) lies on the SM2 curve y^2 = x^3 + ax + b mod p."""
    x, y = mpz(x), mpz(y)
    if not (0 <= x < SM2_P and 0 <= y < SM2_P):
        return False
    lhs = (y * y) % SM2_P
    rhs = (x * x * x + SM2_A * x + SM2_B) % SM2_P
    return lhs == rhs


def bytes_to_point(data):
    """Decode an uncompressed point (04 || x || y) to affine (x, y) with on-curve check."""
    if len(data) == 65 and data[0] == 0x04:
        x = mpz(int.from_bytes(data[1:33], 'big'))
        y = mpz(int.from_bytes(data[33:65], 'big'))
        if not is_on_curve(x, y):
            raise ValueError("Point is not on SM2 curve")
        return (x, y)
    raise ValueError("Unsupported point encoding")
