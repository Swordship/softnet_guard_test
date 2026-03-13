import pandas as pd

print("=" * 60)
print("  SoftNet-Guard CSV Diagnostic")
print("=" * 60)

# UNSW-NB15
try:
    df1 = pd.read_csv('UNSW-NB15_1.csv', nrows=3)
    print("\n[UNSW-NB15]")
    print("  All columns:", list(df1.columns))
    print("  Last 5 cols:", list(df1.columns)[-5:])
    print("  Shape (3 rows):", df1.shape)
    print("  First row values (last 5):", df1.iloc[0, -5:].tolist())
except Exception as e:
    print(f"  ERROR: {e}")

# TON-IoT (try comma first, then semicolon)
try:
    df2 = pd.read_csv('ton-iot.csv', nrows=3)
    print("\n[TON-IoT - comma]")
    print("  All columns:", list(df2.columns))
    print("  Shape (3 rows):", df2.shape)
    print("  First row values (first 5):", df2.iloc[0, :5].tolist())
except Exception as e:
    print(f"  ERROR (comma): {e}")

try:
    df2b = pd.read_csv('ton-iot.csv', nrows=3, sep=';')
    print("\n[TON-IoT - semicolon]")
    print("  All columns:", list(df2b.columns))
    print("  Shape (3 rows):", df2b.shape)
except Exception as e:
    print(f"  ERROR (semicolon): {e}")

# PhiUSIIL
try:
    df3 = pd.read_csv('PhiUSIIL_Phishing_URL_Dataset.csv', nrows=3)
    print("\n[PhiUSIIL]")
    print("  All columns:", list(df3.columns))
    print("  Shape (3 rows):", df3.shape)
    print("  First row values (first 5):", df3.iloc[0, :5].tolist())
except Exception as e:
    print(f"  ERROR: {e}")

print("\n" + "=" * 60)
print("  Copy and paste the full output above to Claude.")
print("=" * 60)