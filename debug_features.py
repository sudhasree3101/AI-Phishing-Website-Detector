import sys, pandas as pd, numpy as np, random
sys.path.insert(0, '.')
from src.feature_extraction import extract_features, FEATURE_NAMES

df = pd.read_csv('data/raw/PhiUSIIL_Phishing_URL_Dataset.csv', usecols=['URL','label'])
legit_urls = df[df['label']==1]['URL'].tolist()
phish_urls = df[df['label']==0]['URL'].tolist()

random.seed(42)
legit_s = random.sample(legit_urls, 500)
phish_s = random.sample(phish_urls, 500)

def avg_feat(urls):
    return np.mean([extract_features(u) for u in urls], axis=0)

la = avg_feat(legit_s)
pa = avg_feat(phish_s)

print('=== DISTRIBUTION ANALYSIS ===')
print(f'{"Feature":<30} {"Legit-avg":>10} {"Phish-avg":>10}')
for i, n in enumerate(FEATURE_NAMES):
    print(f'{n:<30} {la[i]:>10.4f} {pa[i]:>10.4f}')

print()
print('=== google.com vs distributions ===')
goog = extract_features('https://google.com')
for i, n in enumerate(FEATURE_NAMES):
    v = goog[i]
    dl = abs(v - la[i])
    dp = abs(v - pa[i])
    closer = 'LEGIT' if dl <= dp else 'PHISH'
    print(f'{n:<30}: val={v:.4f}  legit={la[i]:.4f}  phish={pa[i]:.4f}  -> {closer}')
