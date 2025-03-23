import itertools
from collections import Counter

def create_playfair_grid(keyword):
    keyword = keyword.upper().replace('J', 'I').replace(' ', '')
    seen = set()
    key_letters = []
    for char in keyword:
        if char.isalpha() and char not in seen:
            key_letters.append(char)
            seen.add(char)
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    for char in alphabet:
        if char not in seen:
            key_letters.append(char)
    return [key_letters[i*5:(i+1)*5] for i in range(5)]

def preprocess(text):
    text = text.upper().replace('J', 'I').replace(' ', '')
    text = ''.join([c for c in text if c.isalpha()]) 
    processed = []
    i = 0
    while i < len(text):
        if i == len(text)-1 or text[i] == text[i+1]:
            processed.append(text[i] + 'X')
            i += 1
        else:
            processed.append(text[i] + text[i+1])
            i += 2
    return processed

def encrypt_decrypt_digraph(grid, digraph, mode):
    a, b = digraph[0], digraph[1]
    try:
        row_a, col_a = next((r, c) for r, row in enumerate(grid) for c, ch in enumerate(row) if ch == a)
        row_b, col_b = next((r, c) for r, row in enumerate(grid) for c, ch in enumerate(row) if ch == b)
    except StopIteration:
        raise ValueError(f"Character '{a}' or '{b}' not found in the Playfair grid.")
    
    if mode == 'encrypt':
        shift = 1
    else:
        shift = -1
    
    if row_a == row_b:
        return grid[row_a][(col_a+shift)%5] + grid[row_b][(col_b+shift)%5]
    elif col_a == col_b:
        return grid[(row_a+shift)%5][col_a] + grid[(row_b+shift)%5][col_b]
    else:
        return grid[row_a][col_b] + grid[row_b][col_a]

def playfair(text, keyword, mode='encrypt'):
    grid = create_playfair_grid(keyword)
    digraphs = preprocess(text) if mode == 'encrypt' else [text[i:i+2] for i in range(0, len(text), 2)]
    processed = [encrypt_decrypt_digraph(grid, d, mode) for d in digraphs]
    return ''.join(processed)

# attacks
def frequency_attack(ciphertext):
    digraphs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
    freq = Counter(digraphs).most_common()
    
    
    common_bigrams = ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ES', 'ON', 'ST', 'NT']
    
    print("\nFrequency Analysis Attack:")
    print(f"Top ciphertext digraphs: {[f[0] for f in freq[:5]]}")
    print(f"Possible substitutions: {dict(zip([f[0] for f in freq[:len(common_bigrams)]], common_bigrams))}")

def known_plaintext_attack(plaintext_pair, ciphertext_pair, ciphertext):
    grid = [['' for _ in range(5)] for _ in range(5)]
    p1, p2 = plaintext_pair[0], plaintext_pair[1]
    c1, c2 = ciphertext_pair[0], ciphertext_pair[1]
    
    print("\nKnown Plaintext Attack:")
    print(f"Assuming {plaintext_pair} → {ciphertext_pair}:")
    print(f"{p1} must be in same row/column as {c1}")
    print(f"{p2} must be in same row/column as {c2}")

def grid_reconstruction_attack(ciphertext, common_keywords):
    print("\nGrid Reconstruction Attack:")
    for kw in common_keywords:
        try_grid = create_playfair_grid(kw)
        attempt = playfair(ciphertext, kw, 'decrypt')
        x_count = attempt.count('X')
        print(f"Keyword '{kw}': Decrypted → {attempt} (X-count: {x_count})")

def filler_attack(decrypted_text):
    print("\nFiller Exploit Attack:")
    modified = []
    i = 0
    while i < len(decrypted_text):
        if i < len(decrypted_text)-1 and decrypted_text[i+1] == 'X':
            modified.append(decrypted_text[i])  
            i += 2
        else:
            modified.append(decrypted_text[i])  
            i += 1
    print(f"Original: {decrypted_text}")
    print(f"After X-removal: {''.join(modified)}")

#vars
PLAINTEXT = """
TASKFORCESEVENTYEIGHTHASSTARTEDOPERATIONNEPTUNEVIGILASOFZEROTWOTHREEZEROHOURSONMARCHTWENTYFIVECARRIERSTRIKEGROUPTWOLEFTPEARLHARBORATTWOTWOONESIXHOURSONMARCHTWENTYFIVEANDISMOVINGTOGRIDFOURTEENNORTHONEHUNDREDTHIRTYFIVEEASTDESTROYERSQUADRONELEVENISESCORTINGUSSRANGERWITHUSSMCCLUSKYANDUSSPORTERONTHEWAYTOTHEMARSHALLISLANDSAMPHIBIOUSREADYGROUPSIXHASLOADEDTHESECONDMARINEEXPEDITIONARYUNITANDWILLMEETTASKFORCESEVENTYEIGHTATFIFTEENSOUTHONEHUNDREDFORTYSEVENEASTBYZEROZEROONETWOHOURSONMARCHTWENTYFIVESUBMARINETASKUNITTWENTYONEFOURHASLEFTGUAMANDISON SILENTPATROLALONGSEALANEGRIDELEVENNORTHONEHUNDREDTHIRTYSEVENEAST
INTELLIGENCEREPORTSSHOWINCREASEDENEMYNAVALACTIVITYSOUTHOFOKINAWAALLUNITSMUSTSTAYATREADINESSCONDITIONYELLOWELECTRONICEMISSIONSCONTROLALPHAISINEFFECTUSNSBRIDGEWILLREFUELCARRIERSTRIKEGROUPTWOATZEROZEROZEROEIGHTHOURSONMARCHTWENTYFIVEATGRIDTENNORTHONEHUNDREDTHIRTYEASTUSNSPATUXENTISHEADINGTOREFUELAMPHIBIOUSREADYGROUPSIXNEARTHESOLOMONISLANDSFUELLEVELSAREACCEPTABLEANDREFUELINGWILLCONTINUEASPLANNED
RULESOFENGAGEMENTSAYTHATSHIPSMUSTNOTFIREUNLESSUNDERATTACKALLUNKNOWNSHIPSMUSTBEREPORTEDONSECURECHANNELBRAVOFRIENDLYSIGNALSAREREDCASTLEFORVISUALIDENTIFICATIONANDBLUEHORIZONFORRADIOCHECKCOMMANDREMAINSWITHNAVALPACIFICFLEETBUTTASKFORCESEVENTYEIGHTCANTAKEEMERGENCYACTIONSIFNEEDEDTHENEXTREPORTISDUEATZEROZEROONETWOHOURSONMARCHTWENTYFIVE
"""
KEYWORD = "BAGRATION"
COMMON_KEYWORDS = ["ZERO", "ONE", "HOURS", "TWO"]

ciphertext = playfair(PLAINTEXT, KEYWORD)
decrypted = playfair(ciphertext, KEYWORD, 'decrypt')

print(f"Original: {PLAINTEXT}")
print(f"Encrypted: {ciphertext}")
print(f"Decrypted: {decrypted}\n")

frequency_attack(ciphertext)
known_plaintext_attack('TA', ciphertext[:2], ciphertext)
grid_reconstruction_attack(ciphertext, COMMON_KEYWORDS)
filler_attack(decrypted)