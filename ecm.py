import random
import math
import sys

def gcd(a, b):
    while(b):
        a, b = b, a%b
    return a

def mod_inv(a, n):
    t, new_t = 0, 1
    r, new_r = n, a
    while new_r != 0:
        quotient = r // new_r;
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r>1:
        return None
    return t%n

def elliptic_add(P, Q, a, N):
    if (P == "O"):
        return Q
    if (Q == "O"):
        return P
    
    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and y1 == -(y2 % N):
        return "O"
    
    if P == Q:
        num = (3*x1*x1 + a) % N
        den = (2*y1) % N
    else:
        num = (y2 - y1) % N
        den = (x2 - x1) % N
    
    inv_den = mod_inv(den, N)
    if inv_den is None:
        return gcd(den, N)
    
    lam = (num * inv_den) % N
    x3 = (lam * lam - x1 - x2) % N
    y3 = (lam * (x1 - x3) - y1) % N

    return (x3, y3)

def scalar_mult(k, P, a, N):
    R = "O"
    while k:
        if k&1:
            R = elliptic_add(R, P, a, N);
            if isinstance(R, int):
                return R
        P = elliptic_add(P, P, a, N)
        if isinstance(P, int):
            return P
        k >>= 1
    return R

def elliptic_curve_factorization(N, B=50):
    while True:
        x0 = random.randint(1, N-1)
        y0 = random.randint(1, N-1)
        a = random.randint(1, N-1)
        b = (y0 ** 2 - x0 ** 3 - a * x0) % N
        P = (x0, y0)

        k = 1
        for p in range(2, B + 1):
            if all(p % d != 0 for d in range(2, int(math.sqrt(p)) + 1)):
                k *= p ** int(math.log(B, p));

        factor = scalar_mult(k, P, a, N)
        if isinstance(factor, int) and factor != 1 and factor != N:
            return factor
        
if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            N = int(sys.argv[1])
        except ValueError:
            print("Error: Please provide a valid integer for N")
            sys.exit(1)
    else:
        N = int(input("Enter the value of N: "))

    factor = elliptic_curve_factorization(N)
    print(f"Found factor: {factor}")

