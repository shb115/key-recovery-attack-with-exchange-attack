import re
from collections import Counter

filename = 'Results.txt'

try:
    # 1. 파일 읽기
    with open(filename, 'r', encoding='utf-8') as f:
        log_content = f.read()

    # 2. 데이터 추출
    pairs = [int(x) for x in re.findall(r'Pairs Found: (\d+)', log_content)]
    total_count = len(pairs)

    if total_count > 0:
        # 3. 계산
        # 평균
        average = sum(pairs) / total_count
        
        # 0의 등장 비율
        zero_count = pairs.count(0)
        zero_ratio = (zero_count / total_count) * 100
        
        # 전체 분포 (오름차순 정렬)
        distribution = dict(sorted(Counter(pairs).items()))

        # 4. 결과 출력
        print(f"평균 (Mean): {average:.4f}")
        print(f"0의 등장 비율: {zero_ratio:.2f}% ({zero_count}/{total_count})")
        print("전체 분포 (값: 횟수):")
        for key, value in distribution.items():
            print(f"  {key}: {value}")
            
    else:
        print("데이터가 없습니다.")

except FileNotFoundError:
    print(f"Error: '{filename}' 파일을 찾을 수 없습니다.")