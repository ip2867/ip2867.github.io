import struct

# 1. 打包数据 (小端序, 8字节)
payload = struct.pack('<Q', 0xD71DC7B2)

# 2. 列表推导式核心逻辑：
#    对于 payload 中的每个字节 b：
#    直接格式化成 "0x" 开头，后面跟 2位十六进制
formatted_output = ", ".join(f"0x{b:02x}" for b in payload)

print(formatted_output)
print('1'*21)