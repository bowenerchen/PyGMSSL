"""
SM9 BN curve field arithmetic and pairing.

Extension field tower: Fp -> Fp2 (u^2+2=0) -> Fp4 (v^2-u=0) -> Fp12 (w^3-v=0)
R-ate pairing on BN curve with parameters from GM/T 0044-2016.
"""

import gmpy2
from gmpy2 import mpz

SM9_P = mpz(0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D)
SM9_N = mpz(0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25)
SM9_B = mpz(5)
SM9_T = mpz(0x600000000058F98A)

SM9_G1X = mpz(0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD)
SM9_G1Y = mpz(0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616)

SM9_G2X0 = mpz(0x85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141)
SM9_G2X1 = mpz(0x3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B)
SM9_G2Y0 = mpz(0x17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96)
SM9_G2Y1 = mpz(0xA7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7)

_P = SM9_P

# --- Fp2 = Fp[u] / (u^2 + 2) ---

class Fp2:
    __slots__ = ('c0', 'c1')

    def __init__(self, c0, c1=mpz(0)):
        self.c0 = mpz(c0) % _P
        self.c1 = mpz(c1) % _P

    def __add__(self, o):
        return Fp2((self.c0 + o.c0) % _P, (self.c1 + o.c1) % _P)

    def __sub__(self, o):
        return Fp2((self.c0 - o.c0) % _P, (self.c1 - o.c1) % _P)

    def __neg__(self):
        return Fp2((-self.c0) % _P, (-self.c1) % _P)

    def __mul__(self, o):
        if isinstance(o, (int, mpz)):
            return Fp2((self.c0 * o) % _P, (self.c1 * o) % _P)
        a0b0 = self.c0 * o.c0
        a1b1 = self.c1 * o.c1
        return Fp2((a0b0 - 2 * a1b1) % _P,
                    ((self.c0 + self.c1) * (o.c0 + o.c1) - a0b0 - a1b1) % _P)

    def __eq__(self, o):
        if isinstance(o, int):
            return self.c0 == o % _P and self.c1 == 0
        return self.c0 == o.c0 and self.c1 == o.c1

    def sqr(self):
        return self * self

    def inv(self):
        t = gmpy2.invert((self.c0 * self.c0 + 2 * self.c1 * self.c1) % _P, _P)
        return Fp2((self.c0 * t) % _P, ((-self.c1) * t) % _P)

    def conj(self):
        return Fp2(self.c0, (-self.c1) % _P)

    def is_zero(self):
        return self.c0 == 0 and self.c1 == 0

FP2_ZERO = Fp2(0, 0)
FP2_ONE = Fp2(1, 0)
FP2_U = Fp2(0, 1)

# --- Fp4 = Fp2[v] / (v^2 - u) ---

class Fp4:
    __slots__ = ('c0', 'c1')

    def __init__(self, c0, c1=FP2_ZERO):
        self.c0 = c0
        self.c1 = c1

    def __add__(self, o):
        return Fp4(self.c0 + o.c0, self.c1 + o.c1)

    def __sub__(self, o):
        return Fp4(self.c0 - o.c0, self.c1 - o.c1)

    def __neg__(self):
        return Fp4(-self.c0, -self.c1)

    def __mul__(self, o):
        if isinstance(o, Fp2):
            return Fp4(self.c0 * o, self.c1 * o)
        if isinstance(o, (int, mpz)):
            return Fp4(self.c0 * o, self.c1 * o)
        a0b0 = self.c0 * o.c0
        a1b1 = self.c1 * o.c1
        return Fp4(a0b0 + a1b1 * FP2_U,
                    (self.c0 + self.c1) * (o.c0 + o.c1) - a0b0 - a1b1)

    def __eq__(self, o):
        return self.c0 == o.c0 and self.c1 == o.c1

    def sqr(self):
        return self * self

    def inv(self):
        t = (self.c0.sqr() - self.c1.sqr() * FP2_U).inv()
        return Fp4(self.c0 * t, -(self.c1 * t))

    def conj(self):
        return Fp4(self.c0, -self.c1)

FP4_ZERO = Fp4(FP2_ZERO, FP2_ZERO)
FP4_ONE = Fp4(FP2_ONE, FP2_ZERO)

# --- Fp12 = Fp4[w] / (w^3 - v), v is the Fp4 element (0, 1) ---

class Fp12:
    __slots__ = ('c0', 'c1', 'c2')

    def __init__(self, c0, c1=FP4_ZERO, c2=FP4_ZERO):
        self.c0 = c0
        self.c1 = c1
        self.c2 = c2

    def __mul__(self, o):
        a0, a1, a2 = self.c0, self.c1, self.c2
        b0, b1, b2 = o.c0, o.c1, o.c2
        t0 = a0 * b0
        t1 = a1 * b1
        t2 = a2 * b2
        v = Fp4(FP2_ZERO, FP2_ONE)
        c0 = t0 + ((a1 + a2) * (b1 + b2) - t1 - t2) * v
        c1 = (a0 + a1) * (b0 + b1) - t0 - t1 + t2 * v
        c2 = (a0 + a2) * (b0 + b2) - t0 - t2 + t1
        return Fp12(c0, c1, c2)

    def sqr(self):
        return self * self

    def inv(self):
        v = Fp4(FP2_ZERO, FP2_ONE)
        a0, a1, a2 = self.c0, self.c1, self.c2
        t0 = a0.sqr() - a1 * a2 * v
        t1 = a2.sqr() * v - a0 * a1
        t2 = a1.sqr() - a0 * a2
        k = ((a2 * t1 + a1 * t2) * v + a0 * t0).inv()
        return Fp12(t0 * k, t1 * k, t2 * k)

    def __eq__(self, o):
        return self.c0 == o.c0 and self.c1 == o.c1 and self.c2 == o.c2

    def pow(self, exp):
        exp = mpz(exp)
        result = FP12_ONE
        base = self
        while exp > 0:
            if exp & 1:
                result = result * base
            base = base.sqr()
            exp >>= 1
        return result

    def to_bytes(self):
        parts = []
        for c in (self.c0, self.c1, self.c2):
            for f2 in (c.c0, c.c1):
                parts.append(int(f2.c0).to_bytes(32, 'big'))
                parts.append(int(f2.c1).to_bytes(32, 'big'))
        return b''.join(parts)

FP12_ONE = Fp12(FP4_ONE, FP4_ZERO, FP4_ZERO)

# --- G1 (E(Fp): y^2 = x^3 + 5) ---

class G1Point:
    __slots__ = ('x', 'y', 'inf')

    def __init__(self, x, y, inf=False):
        self.x = mpz(x)
        self.y = mpz(y)
        self.inf = inf

    @staticmethod
    def infinity():
        return G1Point(0, 0, True)

    @staticmethod
    def is_on_curve(x, y):
        """Check whether (x, y) lies on E(Fp): y^2 = x^3 + 5."""
        x, y = mpz(x), mpz(y)
        if not (0 <= x < _P and 0 <= y < _P):
            return False
        lhs = (y * y) % _P
        rhs = (x * x * x + SM9_B) % _P
        return lhs == rhs

SM9_G1 = G1Point(SM9_G1X, SM9_G1Y)

def g1_double(P):
    if P.inf:
        return G1Point.infinity()
    lam = (3 * P.x * P.x) * gmpy2.invert(2 * P.y, _P) % _P
    x3 = (lam * lam - 2 * P.x) % _P
    y3 = (lam * (P.x - x3) - P.y) % _P
    return G1Point(x3, y3)

def g1_add(P, Q):
    if P.inf: return Q
    if Q.inf: return P
    if P.x == Q.x:
        if P.y == Q.y:
            return g1_double(P)
        return G1Point.infinity()
    lam = ((Q.y - P.y) * gmpy2.invert(Q.x - P.x, _P)) % _P
    x3 = (lam * lam - P.x - Q.x) % _P
    y3 = (lam * (P.x - x3) - P.y) % _P
    return G1Point(x3, y3)

def g1_neg(P):
    if P.inf: return P
    return G1Point(P.x, (-P.y) % _P)

def g1_mul(k, P):
    k = mpz(k) % SM9_N
    R = G1Point.infinity()
    Q = P
    while k > 0:
        if k & 1:
            R = g1_add(R, Q)
        Q = g1_double(Q)
        k >>= 1
    return R

# --- G2 (twist E'(Fp2): y^2 = x^3 + b/u) ---

class G2Point:
    __slots__ = ('x', 'y', 'inf')

    def __init__(self, x, y, inf=False):
        self.x = x
        self.y = y
        self.inf = inf

    @staticmethod
    def infinity():
        return G2Point(FP2_ZERO, FP2_ZERO, True)

SM9_G2 = G2Point(Fp2(SM9_G2X0, SM9_G2X1), Fp2(SM9_G2Y0, SM9_G2Y1))


def _is_sm9_g2_generator(P: G2Point) -> bool:
    return not P.inf and P.x == SM9_G2.x and P.y == SM9_G2.y


def g2_double(P):
    if P.inf:
        return G2Point.infinity()
    lam = P.x.sqr() * 3 * (P.y * 2).inv()
    x3 = lam.sqr() - P.x * 2
    y3 = lam * (P.x - x3) - P.y
    return G2Point(x3, y3)

def g2_add(P, Q):
    from gmssl._backends._sm9_gmssl_native import gmssl_lib_available, native_g2_add

    if gmssl_lib_available():
        if P.inf:
            return Q
        if Q.inf:
            return P
        return native_g2_add(P, Q)
    if P.inf:
        return Q
    if Q.inf:
        return P
    if P.x == Q.x:
        if P.y == Q.y:
            return g2_double(P)
        return G2Point.infinity()
    lam = (Q.y - P.y) * (Q.x - P.x).inv()
    x3 = lam.sqr() - P.x - Q.x
    y3 = lam * (P.x - x3) - P.y
    return G2Point(x3, y3)

def g2_neg(P):
    if P.inf: return P
    return G2Point(P.x, -P.y)

def g2_mul(k, P):
    from gmssl._backends._sm9_gmssl_native import (
        gmssl_lib_available,
        native_g2_mul,
        native_g2_mul_generator,
    )

    k = mpz(k) % SM9_N
    if gmssl_lib_available():
        if P.inf:
            return G2Point.infinity()
        if _is_sm9_g2_generator(P):
            return native_g2_mul_generator(int(k))
        return native_g2_mul(int(k), P)
    R = G2Point.infinity()
    Q = P
    while k > 0:
        if k & 1:
            R = g2_add(R, Q)
        Q = g2_double(Q)
        k >>= 1
    return R

# --- R-ate pairing ---

def _line_func(T, Q, P):
    """Compute line function for Miller loop.
    T, Q in G2 (Fp2 coords), P in G1 (Fp coords).
    Returns Fp12 element.
    """
    if T.x == Q.x and T.y == Q.y:
        lam = T.x.sqr() * 3 * (T.y * 2).inv()
    elif T.x == Q.x:
        return None
    else:
        lam = (Q.y - T.y) * (Q.x - T.x).inv()

    Px = Fp2(P.x, 0)
    Py = Fp2(P.y, 0)

    a = lam * (T.x - Px) - (T.y - Py)
    b = -lam
    c = FP2_ONE

    return Fp12(Fp4(a, FP2_ZERO), Fp4(b, FP2_ZERO), Fp4(c, FP2_ZERO))


def _frobenius_g2(Q, power):
    """Apply Frobenius endomorphism to G2 point."""
    if Q.inf:
        return Q
    if power == 1:
        x_conj = Q.x.conj()
        y_conj = Q.y.conj()
        alpha = Fp2(
            mpz(0x3F23EA58E5720BDB843C6CFE5E969564B2DE09B67A8DE21C0EC8404FC3F24D0),
            mpz(0xAD54CF9199C2B3FF0B3B8FA7C3F7A0E5DCDA1A68F83BA7CA0078E0AAAFB6E4A7)
        )
        beta = Fp2(
            mpz(0xF300000002A3A6F2780272354F8B78F4D5FC11967BE65334),
            mpz(0x6215BBA5C999A7C7A7CF28D519BE3DA65F3170153D278FF2)
        )
        return G2Point(x_conj * alpha, y_conj * beta)
    elif power == 2:
        alpha2 = Fp2(
            mpz(0xF300000002A3A6F2780272354F8B78F4D5FC11967BE65333),
            0
        )
        return G2Point(Q.x * alpha2, Q.y)
    return Q


def rate_pairing(P, Q):
    """R-ate pairing e(P, Q) for P in G1, Q in G2. Returns Fp12."""
    if P.inf or Q.inf:
        return FP12_ONE

    a = mpz(0x2400000000215D93E)

    T = G2Point(Fp2(Q.x.c0, Q.x.c1), Fp2(Q.y.c0, Q.y.c1))
    f = FP12_ONE

    bits = []
    temp = a
    while temp > 0:
        bits.append(int(temp & 1))
        temp >>= 1
    bits.reverse()

    for i in range(1, len(bits)):
        f = f.sqr()
        lv = _line_func(T, T, P)
        if lv is not None:
            f = f * lv
        T = g2_double(T)

        if bits[i] == 1:
            lv = _line_func(T, Q, P)
            if lv is not None:
                f = f * lv
            T = g2_add(T, Q)

    Q1 = _frobenius_g2(Q, 1)
    Q2 = g2_neg(_frobenius_g2(Q, 2))

    lv = _line_func(T, Q1, P)
    if lv is not None:
        f = f * lv
    T = g2_add(T, Q1)

    lv = _line_func(T, Q2, P)
    if lv is not None:
        f = f * lv

    return _final_exp(f)


def _final_exp(f):
    """Final exponentiation: f^((p^12 - 1) / n)."""
    p = _P
    t = f.inv()
    f2 = Fp12(f.c0.conj(), -f.c1.conj(), f.c2.conj())
    f = f2 * t

    f2 = Fp12(f.c0, f.c1, f.c2)
    # f = f^(p^2) * f  (easy part)
    fp2 = _fp12_frobenius(f, 2)
    f = fp2 * f

    # Hard part using BN-specific formula
    a = f.pow(SM9_T)
    b = a.pow(SM9_T)
    c = b.pow(SM9_T)

    fp1 = _fp12_frobenius(f, 1)
    fp2_ = _fp12_frobenius(f, 2)
    fp3 = _fp12_frobenius(f, 3)
    ap = _fp12_frobenius(a, 1)
    bp = _fp12_frobenius(b, 1)
    bp2 = _fp12_frobenius(b, 2)
    cp = _fp12_frobenius(c, 1)

    y0 = fp1 * fp2_ * fp3
    y1 = f.inv()
    y2 = bp2
    y3 = ap
    y4 = a * bp
    y4 = y4.inv()
    y5 = b.inv()
    y6 = c * cp
    y6 = y6.inv()

    t0 = y6.sqr() * y4 * y5
    t1 = y3 * y5 * t0
    t0 = t0 * y2
    t1 = t1.sqr() * t0
    t1 = t1.sqr()
    t0 = t1 * y1
    t1 = t1 * y0
    t0 = t0.sqr()
    result = t0 * t1

    return result


def _fp12_frobenius(f, k):
    """Compute f^(p^k) using conjugation in Fp12."""
    if k == 0:
        return f
    if k == 1:
        c0 = Fp4(f.c0.c0.conj(), f.c0.c1.conj())
        c1 = Fp4(f.c1.c0.conj(), f.c1.c1.conj())
        c2 = Fp4(f.c2.c0.conj(), f.c2.c1.conj())
        w1 = Fp2(
            mpz(0x3F23EA58E5720BDB843C6CFE5E969564B2DE09B67A8DE21C0EC8404FC3F24D0),
            mpz(0xAD54CF9199C2B3FF0B3B8FA7C3F7A0E5DCDA1A68F83BA7CA0078E0AAAFB6E4A7)
        )
        w2 = w1.sqr()
        w3 = w1 * w2
        c1 = c1 * w1
        c2 = c2 * w2
        return Fp12(c0, c1, c2)
    elif k == 2:
        w1_2 = Fp2(mpz(0xF300000002A3A6F2780272354F8B78F4D5FC11967BE65333), 0)
        w2_2 = w1_2 * w1_2
        c0 = f.c0
        c1 = Fp4(f.c1.c0 * w1_2, f.c1.c1 * w1_2)
        c2 = Fp4(f.c2.c0 * w2_2, f.c2.c1 * w2_2)
        return Fp12(c0, c1, c2)
    elif k == 3:
        return _fp12_frobenius(_fp12_frobenius(f, 1), 2)
    return f
