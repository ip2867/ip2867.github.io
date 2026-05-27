import base64
import string

def decode_custom_base64(ciphertext, custom_table):
    """
    解密换表 Base64
    :param ciphertext: 需要解密的密文字符串
    :param custom_table: 在 IDA 中找到的 64 位自定义索引表
    :return: 解密后的 bytes 数据
    """
    # 1. 定义标准的 Base64 索引表
    standard_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    # 检查表长度必须是 64
    if len(custom_table) != 64:
        print(f"[-] 错误: 自定义表长度为 {len(custom_table)}，必须是 64 位。")
        return None

    # 2. 利用 maketrans 创建映射关系： 自定义表 -> 标准表
    # 原理：把密文中属于自定义表的字符，替换成标准表中对应位置的字符
    trans_map = str.maketrans(custom_table, standard_table)
    
    # 3. 替换字符串
    std_ciphertext = ciphertext.translate(trans_map)
    print(f"[*] 映射回标准 Base64: {std_ciphertext}")

    # 4. 使用标准 Base64 解码
    # 注意：如果存在 padding '='，通常不需要处理，直接解码即可
    try:
        decoded = base64.b64decode(std_ciphertext)
        return decoded
    except Exception as e:
        print(f"[-] 解码失败: {e}")
        return None

# ================= 配置区域 =================

# 示例：假设这是你在 IDA 中找到的变异表（这里是标准表的倒序，仅作演示）
# 通常在 IDA 的 .data 或 .rdata 段，或者由代码动态生成
my_custom_table = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0987654321/+"

# 假设这是你拿到的密文
my_ciphertext = "mTyqm7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI==" 

# ================= 执行解密 =================

result = decode_custom_base64(my_ciphertext, my_custom_table)

if result:
    print("-" * 30)
    print(f"[+] 解密结果 (Bytes): {result}")
    try:
        # 尝试转成字符串显示
        print(f"[+] 解密结果 (String): {result.decode('utf-8')}")
    except:
        print("[!] 结果包含非文本字符，无法直接转为 UTF-8 字符串")
