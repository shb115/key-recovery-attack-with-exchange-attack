import re
from collections import Counter

filename = 'Results.txt'

try:
    # read the log of the previous version
    with open(filename, 'r', encoding='utf-8') as f:
        log_content = f.read()

    # extract the number of pairs found per trial
    pairs = [int(x) for x in re.findall(r'Pairs Found: (\d+)', log_content)]
    total_count = len(pairs)

    if total_count > 0:
        # statistics
        average = sum(pairs) / total_count
        
        # fraction of trials with no pair
        zero_count = pairs.count(0)
        zero_ratio = (zero_count / total_count) * 100
        
        # distribution
        distribution = dict(sorted(Counter(pairs).items()))

        print(f"Mean: {average:.4f}")
        print(f"Trials with no pair: {zero_ratio:.2f}% ({zero_count}/{total_count})")
        print("Distribution (pairs: trials):")
        for key, value in distribution.items():
            print(f"  {key}: {value}")
            
    else:
        print("No data.")

except FileNotFoundError:
    print(f"Error: '{filename}' not found.")