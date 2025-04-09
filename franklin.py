import sympy
import random
from math import gcd

def generate_rsa_key(bits=512):
    # Generate two large prime numbers
    e = 3  # Small e for demonstration purposes - makes polynomial GCD easier
    
    # Find primes such that gcd(e, p-1) = 1 and gcd(e, q-1) = 1
    while True:
        p = sympy.randprime(2**(bits//2-1), 2**(bits//2))
        if gcd(e, p-1) == 1:
            break
    
    while True:
        q = sympy.randprime(2**(bits//2-1), 2**(bits//2))
        if q != p and gcd(e, q-1) == 1:
            break
    
    # Calculate n and Euler's totient function
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # At this point, e and phi are guaranteed to be coprime
    # Calculate d, the modular multiplicative inverse of e (mod phi)
    d = sympy.mod_inverse(e, phi)
    
    return (e, n), (d, n)

def encrypt(message, public_key):
    e, n = public_key
    return pow(message, e, n)

def decrypt(ciphertext, private_key):
    d, n = private_key
    return pow(ciphertext, d, n)

def extended_gcd(a, b):
    """Extended Euclidean Algorithm to find gcd and coefficients"""
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def mod_inverse(a, m):
    """Calculate the modular multiplicative inverse of a mod m"""
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

# Polynomial operations for the Franklin-Reiter attack
class Polynomial:
    def __init__(self, coeffs, modulus):
        """Initialize a polynomial with coefficients and modulus"""
        self.coeffs = coeffs
        self.modulus = modulus
        self._normalize()
    
    def _normalize(self):
        """Remove leading zero coefficients"""
        while len(self.coeffs) > 1 and self.coeffs[-1] == 0:
            self.coeffs.pop()
    
    def __add__(self, other):
        """Add two polynomials"""
        if not isinstance(other, Polynomial):
            raise TypeError("Can only add polynomials")
        if self.modulus != other.modulus:
            raise ValueError("Polynomials must have the same modulus")
        
        result = [0] * max(len(self.coeffs), len(other.coeffs))
        for i in range(len(self.coeffs)):
            result[i] = (result[i] + self.coeffs[i]) % self.modulus
        for i in range(len(other.coeffs)):
            result[i] = (result[i] + other.coeffs[i]) % self.modulus
        
        return Polynomial(result, self.modulus)
    
    def __mul__(self, other):
        """Multiply two polynomials"""
        if not isinstance(other, Polynomial):
            raise TypeError("Can only multiply polynomials")
        if self.modulus != other.modulus:
            raise ValueError("Polynomials must have the same modulus")
        
        result = [0] * (len(self.coeffs) + len(other.coeffs) - 1)
        for i in range(len(self.coeffs)):
            for j in range(len(other.coeffs)):
                result[i + j] = (result[i + j] + self.coeffs[i] * other.coeffs[j]) % self.modulus
        
        return Polynomial(result, self.modulus)
    
    def __mod__(self, other):
        """Compute self modulo other polynomial"""
        if not isinstance(other, Polynomial):
            raise TypeError("Can only compute modulo with polynomials")
        if self.modulus != other.modulus:
            raise ValueError("Polynomials must have the same modulus")
        
        # If other is of higher degree, just return self
        if len(self.coeffs) < len(other.coeffs):
            return Polynomial(self.coeffs.copy(), self.modulus)
        
        # Perform polynomial long division
        quotient = [0] * (len(self.coeffs) - len(other.coeffs) + 1)
        remainder = self.coeffs.copy()
        
        for i in range(len(self.coeffs) - len(other.coeffs), -1, -1):
            if len(remainder) <= i + len(other.coeffs) - 1:
                continue
            
            if remainder[i + len(other.coeffs) - 1] == 0:
                continue
                
            factor = remainder[i + len(other.coeffs) - 1] * mod_inverse(other.coeffs[-1], self.modulus) % self.modulus
            quotient[i] = factor
            
            for j in range(len(other.coeffs)):
                remainder[i + j] = (remainder[i + j] - factor * other.coeffs[j]) % self.modulus
        
        # Trim trailing zeros
        while len(remainder) > 0 and remainder[-1] == 0:
            remainder.pop()
        
        return Polynomial(remainder, self.modulus)
    
    def degree(self):
        """Return the degree of the polynomial"""
        return len(self.coeffs) - 1
    
    def evaluate(self, x):
        """Evaluate polynomial at point x"""
        result = 0
        for i in range(len(self.coeffs) - 1, -1, -1):
            result = (result * x + self.coeffs[i]) % self.modulus
        return result

def polynomial_gcd(a, b):
    """Compute the greatest common divisor of two polynomials"""
    if b.degree() == -1:  # b is zero polynomial
        return a
    return polynomial_gcd(b, a % b)

def franklin_reiter_attack(n, e, c1, c2, a, b):
    """
    Franklin-Reiter attack on RSA when two related messages are encrypted.
    
    Args:
        n: RSA modulus
        e: RSA public exponent
        c1: First ciphertext (E(m))
        c2: Second ciphertext (E(a*m + b))
        a: Multiplier for the linear relationship
        b: Constant for the linear relationship
    
    Returns:
        The original message m if attack is successful, None otherwise
    """
    # Define polynomials
    # g1(x) = x^e - c1, which has m as a root
    # g2(x) = (ax + b)^e - c2, which also has m as a root
    
    # This only works with small e for our implementation
    if e == 3:
        # For e=3, we can expand (ax+b)^3 directly
        # (ax+b)^3 = a^3*x^3 + 3*a^2*b*x^2 + 3*a*b^2*x + b^3
        
        # Coefficients for x^3 - c1
        g1_coeffs = [(-c1) % n, 0, 0, 1]  # x^3 - c1
        g1 = Polynomial(g1_coeffs, n)
        
        # Coefficients for (ax+b)^3 - c2
        # (ax+b)^3 - c2 = a^3*x^3 + 3*a^2*b*x^2 + 3*a*b^2*x + b^3 - c2
        a_cubed = pow(a, 3, n)
        a_squared_b = (3 * pow(a, 2, n) * b) % n
        a_b_squared = (3 * a * pow(b, 2, n)) % n
        b_cubed = pow(b, 3, n)
        g2_coeffs = [(b_cubed - c2) % n, a_b_squared, a_squared_b, a_cubed]
        g2 = Polynomial(g2_coeffs, n)
        
        try:
            # Compute GCD of the two polynomials
            gcd_poly = polynomial_gcd(g1, g2)
            
            # The GCD should be a linear factor (x - m)
            if gcd_poly.degree() == 1:
                # If gcd = Ax + B, then m = -B/A mod n
                A = gcd_poly.coeffs[1]
                B = gcd_poly.coeffs[0]
                
                if A != 0:
                    A_inv = mod_inverse(A, n)
                    m = (-B * A_inv) % n
                    return m
            
            # If something went wrong, try using brute force for small polynomials
            if gcd_poly.degree() <= 2:
                # Try evaluating at small values
                for i in range(1000):
                    if g1.evaluate(i) == 0 and g2.evaluate(i) == 0:
                        return i
            
            return None
        except Exception as e:
            print(f"Error during attack: {e}")
            return None
    else:
        print("This implementation only works with e=3 for demonstration purposes")
        return None

def demonstrate_attack():
    print("Franklin-Reiter Related Message Attack Demonstration")
    print("===================================================")
    
    # For demonstration, we'll use small numbers and e=3
    bits = 64
    public_key, private_key = generate_rsa_key(bits)
    e, n = public_key
    d, _ = private_key
    
    if e != 3:
        print("This demonstration only works with e=3")
        return
    
    print(f"Generated RSA key pair with {bits} bits")
    print(f"Public key (e, n): ({e}, {n})")
    
    # Choose a small message for demonstration
    message = random.randint(100, 1000)
    print(f"Original message: {message}")
    
    # Define a linear relationship: m2 = a*m1 + b
    a = 2  # Simple multiplier
    b = 7  # Simple constant
    related_message = (a * message + b) % n
    
    print(f"Related message (2*m + 7): {related_message}")
    
    # Encrypt both messages
    c1 = encrypt(message, public_key)
    c2 = encrypt(related_message, public_key)
    
    print(f"Ciphertext 1: {c1}")
    print(f"Ciphertext 2: {c2}")
    
    # Decrypt using private key to verify
    decrypted1 = decrypt(c1, private_key)
    decrypted2 = decrypt(c2, private_key)
    
    print(f"Decrypted message 1 (using private key): {decrypted1}")
    print(f"Decrypted message 2 (using private key): {decrypted2}")
    
    # Now, attempt the Franklin-Reiter attack
    print("\nAttempting Franklin-Reiter attack...")
    
    recovered_message = franklin_reiter_attack(n, e, c1, c2, a, b)
    
    if recovered_message is not None and recovered_message == message:
        print(f"Attack successful! Recovered message: {recovered_message}")
    else:
        print("Attack failed or recovered incorrect message")
        if recovered_message is not None:
            print(f"Recovered value: {recovered_message}")

if __name__ == "__main__":
    # This implementation is for educational purposes and demonstrates
    # the Franklin-Reiter attack with e=3 for simplicity
    demonstrate_attack()