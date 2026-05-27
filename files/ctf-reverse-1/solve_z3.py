import re
from z3 import *

def clean_ida_code_and_solve():
    # ---------------------------------------------------------
    # 1. 把你在 IDA 里看到的那些 if 里面的公式全部复制到下面这两个引号之间
    #    不需要管格式乱不乱，只要包含所有公式就行
    # ---------------------------------------------------------
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
    # ---------------------------------------------------------

    # --- 步骤 1: 预处理 IDA 的特殊符号 ---
    # 去掉多余的换行和空格
    s = ida_code.replace('\n', ' ').strip()
    
    # 处理位移运算: (vX << Y) -> vX * (2^Y)
    # 比如 (v6 << 6) 变成 v6 * 64
    def shift_repl(match):
        var = match.group(1) # 获取变量名，如 v6
        shift_bits = int(match.group(2)) # 获取位移数，如 6
        multiplier = 1 << shift_bits # 计算 2的6次方 = 64
        return f"{var} * {multiplier}"
    
    # 正则匹配类似于 "v6 << 6" 或 "(v6 << 6)" 的结构
    s = re.sub(r'\(?(v\d+)\s*<<\s*(\d+)\)?', shift_repl, s)

    # --- 步骤 2: 将 && 和 return 变成列表 ---
    # 把 '&&' 换成 分隔符
    s = s.replace('&&', '||')
    # 如果有 return 关键字，也去掉
    s = s.replace('return', '')
    
    # --- 步骤 3: 格式化变量 vN -> v[N] ---
    # 定义替换函数，把 v1 变成 v[1]
    def var_repl(match):
        idx = match.group(1)
        return f"v[{idx}]"
    
    # 替换所有 v 后跟数字的情况
    s = re.sub(r'v(\d+)', var_repl, s)

    # 分割成方程列表
    fc_list = [x.strip() for x in s.split('||') if x.strip()]
    
    print(f"检测到 {len(fc_list)} 个方程，开始求解...\n")
    
    # --- 步骤 4: Z3 求解 ---
    # 创建足够大的变量池 (v0 到 v15)
    v = [Int(f'v{i}') for i in range(20)]
    solver = Solver()
    
    for eq in fc_list:
        # 添加约束
        try:
            solver.add(eval(eq))
        except Exception as e:
            print(f"方程解析出错: {eq}\n错误: {e}")
            return

    if solver.check() == sat:
        m = solver.model()
        # 将结果存入字典
        res = {}
        for i in range(20):
            if m[v[i]] is not None:
                res[f'v{i}'] = m[v[i]].as_long()
        
        print("求解成功！原始变量值:", res)
        
        # --- 步骤 5: 根据题目逻辑还原 Flag ---
        # 题目中的赋值逻辑 (请根据你的 IDA 顶部确认):
        # v1 = s[1]; v2 = *s(即s[0]); v3 = s[2]; v4 = s[3]; v5 = s[4];
        # v6 = s[6]; v7 = s[5]; v8 = s[7]; v9 = s[8]; v11 = s[9];
        
        # 注意: v7对应s[5], v6对应s[6] (根据你的代码: v6=s[6], v7=s[5])
        try:
            flag_ascii = [
                res['v2'],  # s[0]
                res['v1'],  # s[1]
                res['v3'],  # s[2]
                res['v4'],  # s[3]
                res['v5'],  # s[4]
                res['v7'],  # s[5]
                res['v6'],  # s[6]
                res['v8'],  # s[7]
                res['v9'],  # s[8]
                res['v11']  # s[9]
            ]
            print("\nFlag 结果: ", end="")
            print("".join([chr(x) for x in flag_ascii]))
        except KeyError as e:
            print(f"\n还原 Flag 失败，缺少变量: {e}")
    else:
        print("无解 (unsat)！请检查方程是否抄错。")

if __name__ == '__main__':
    clean_ida_code_and_solve()
