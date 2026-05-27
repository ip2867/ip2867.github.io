import re
from z3 import *

# IDA 中的校验方程（从伪代码中复制）
ida_code = """
 -85 * v9 + 58 * v8 + 97 * v6 + v7 + -45 * v5 + 84 * v4 + 95 * v2 - 20 * v1 + 12 * v3 == 12613
  && 30 * v11 + -70 * v9 + -122 * v6 + -81 * v7 + -66 * v5 + -115 * v4 + -41 * v3 + -86 * v1 - 15 * v2 - 30 * v8 == -54400
  && -103 * v11 + 120 * v8 + 108 * v7 + 48 * v4 + -89 * v3 + 78 * v1 - 41 * v2 + 31 * v5 - (v6 << 6) - 120 * v9 == -10283
  && 71 * v6 + (v7 << 7) + 99 * v5 + -111 * v3 + 85 * v1 + 79 * v2 - 30 * v4 - 119 * v8 + 48 * v9 - 16 * v11 == 22855
  && 5 * v11 + 23 * v9 + 122 * v8 + -19 * v6 + 99 * v7 + -117 * v5 + -69 * v3 + 22 * v1 - 98 * v2 + 10 * v4 == -2944
  && -54 * v11 + -23 * v8 + -82 * v3 + -85 * v2 + 124 * v1 - 11 * v4 - 8 * v5 - 60 * v7 + 95 * v6 + 100 * v9 == -2222
  && -83 * v11 + -111 * v7 + -57 * v2 + 41 * v1 + 73 * v3 - 18 * v4 + 26 * v5 + 16 * v6 + 77 * v8 - 63 * v9 == -13258
  && 81 * v11 + -48 * v9 + 66 * v8 + -104 * v6 + -121 * v7 + 95 * v5 + 85 * v4 + 60 * v3 + -85 * v2 + 80 * v1 == -1559
  && 101 * v11 + -85 * v9 + 7 * v6 + 117 * v7 + -83 * v5 + -101 * v4 + 90 * v3 + -28 * v1 + 18 * v2 - v8 == 6308
  && 99 * v11 + -28 * v9 + 5 * v8 + 93 * v6 + -18 * v7 + -127 * v5 + 6 * v4 + -9 * v3 + -93 * v1 + 58 * v2 == -1697
"""

# 预处理：位移运算转乘法  (v6 << 6) → v6 * 64
s = ida_code.replace('\n', ' ')
s = re.sub(r'\(?(v\d+)\s*<<\s*(\d+)\)?',
           lambda m: f"({m.group(1)} * {1 << int(m.group(2))})", s)

# 分割方程
equations = [x.strip() for x in s.replace('&&', '||').split('||') if x.strip()]

# 变量格式化：v1 → v[1]
equations = [re.sub(r'v(\d+)', lambda m: f"v[{m.group(1)}]", eq) for eq in equations]

# Z3 求解
v = [Int(f'v{i}') for i in range(20)]
solver = Solver()
for eq in equations:
    solver.add(eval(eq))

if solver.check() == sat:
    m = solver.model()
    res = {f'v{i}': m[v[i]].as_long() for i in range(20) if m[v[i]] is not None}
    print("求解成功！", res)
    # 根据题目中的变量映射关系还原 flag
    # 注意：变量映射关系需要从 IDA 顶部的赋值语句确认
    flag_ascii = [res['v2'], res['v1'], res['v3'], res['v4'], res['v5'],
                  res['v7'], res['v6'], res['v8'], res['v9'], res['v11']]
    print("Flag:", ''.join(chr(x) for x in flag_ascii))
else:
    print("无解！请检查方程是否抄错。")
