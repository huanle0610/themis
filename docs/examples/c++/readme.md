生成受密码保护的master key:

bash
Copy
# 交互式输入密码
./lic_gen -g -o /secure/keys

# 或通过命令行提供密码(安全性较低)
./lic_gen -g -o /secure/keys -p "my_strong_password"
使用受保护的master key签发license:

bash
Copy
# 交互式输入密码
./lic_gen -m /secure/keys/master.key -o /licenses -c client-123

# 或通过命令行提供密码
./lic_gen -m /secure/keys/master.key -p "my_strong_password" -o /licenses -c client-123