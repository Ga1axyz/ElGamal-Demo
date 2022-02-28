#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include <Windows.h>

#include "miracl.h"

#define MAX_D 150						// 安全素数 p 的位数
#define MAX_Digits 1024

int main()
{
	miracl *mip = mirsys(MAX_Digits, 10);			// 初始化MIRACL系统，这里第一个参数定义变量的最大长度是 1024 位，第二个参数定义输入、输出、运算都是采用 10 进制进行

	big p = mirvar(0);			// 大素数		// 通过为变量保留适当数量的内存位置来初始化该变量。这个内存可以通过随后调用mirkill函数来释放
	big p_1 = mirvar(0);			// p-1
	big p_2 = mirvar(0);			// p-2
	big q = mirvar(0);
	big g = mirvar(0);					// 本原元
	big x = mirvar(0);					// 私钥				脱密密钥				随机选取，1 <= x <= p-2
	big y = mirvar(0);					// 公钥				加密密钥				y = g^x mod p
	big m = mirvar(0);					// 明文
	big c1 = mirvar(0), c2 = mirvar(0);			// 密文				c = (c1,c2) , c1 = g^k mod p , c2 = m * y^k mod p
	big de_m = mirvar(0);					// 解密得到的明文	
	big k = mirvar(0);					// 秘密整数			随机选取，1 <= k <= p-2
	big flag = mirvar(0);					// 中间变量
	big temp = mirvar(0);					// 中间变量
	big one = mirvar(1);					// 常量 one = 1
	big r = mirvar(0), s = mirvar(0);			// r = g^k mod p , s = k^(-1) * (m - rx) mod (p-1)			(m,r,s) 为对消息 m 的数字签名

	char msg[151];
	printf_s("请输入明文：");
	scanf_s("%s", msg, 151);				// 通过字符串的方式输入大数
	cinstr(m,msg);						// 将大数字符串转换成大数（Big 类型）
	
	//************************ 密钥生成 ************************//
	{
		irand((unsigned)time(NULL));			// 使用当前时间作为随机数种子，初始化内部随机数系统

		// 随机生成一个安全素数 p
		bigdig(MAX_D, 10, q);				// 产生一个 150 位，10 进制的大随机数 q
		nxsafeprime(0, 0, q, p);			// 生成一个比 q 大的安全素数 p
		copy(p, q);					// 将一个大数赋值给另一个大数		q = p
		decr(q, 1, q);					// 将一个大数减去一个整数			q = q - 1
		subdiv(q, 2, q);				// 将一个大数除以一个整数			q = q / 2	即 q = (p-1)/2 或 p = 2q + 1		q 也是素数
		decr(p, 1, p_1);				// 生成 p_1 = p - 1
		decr(p, 2, p_2);				// 生成 p_2 = p - 2

		// 安全素数 p 条件下构造本原元 g			// 设 p 为安全素数，p = 2q + 1，q = (p-1)/2，且 q 为素数，由 Fermat 定理有，g^(p-1) mod p = 1，即 g^2q mod p = 1，此时，g 是本原元等价于 g^2 mod p != 1 且 g^q mod p != 1
		while (1)
		{
			bigrand(p_1, g);			// 产生一个小于 p-1 的大随机数 g	
			if (compare(g, one) <= 0)		// 保证 g 大于 1						1 < g < p-1
				continue;
			powmod(g, mirvar(2), p, flag);		// 模幂运算
			if (compare(flag, one) != 0)		// flag = g^2 mod p != 1				如果 g^2 mod p != 1
			{
				powmod(g, q, p, flag);			// 模幂运算
				if (compare(flag, one) != 0)		// flag = g^q mod p != 1				如果 g^q mod p != 1
				{
					multiply(q, mirvar(2), flag);	// 两个大数相乘			flag = q * 2
					powmod(g, flag, p, flag);	// flag = g^2q mod p
					if (compare(flag, one) == 0)	// flag == 1				如果 g^2q mod p == 1
						break;
				}
			}
		}

		// 随机选择私钥 x ，1 <= x <= p-2
		irand((unsigned)time(NULL));				// 使用当前时间作为随机数种子 
		while (1)
		{
			bigrand(p_1, x);				// x <= p-2
			if (compare(x, one) >= 0)			// x >= 1
				break;
		}

		// 计算得到公钥 y ，y = g^x mod p
		powmod(g, x, p, y);
		
		printf("\n\n>>【公钥】：\n  p = ");
		cotnum(p, stdout);					// 将大数输出到屏幕
		printf("\n  g = ");
		cotnum(g, stdout);
		printf("\n  y = ");
		cotnum(y, stdout);
		printf("\n>>【私钥】：\n  x = ");
		cotnum(x, stdout);
	}

	//************************ ElGamal 加密变换 ************************//
	{
		// 随机选取整数 k ，1 <= k <= p-2 , (k,p-1) = 1
		irand((unsigned)time(NULL));				// 使用当前时间作为随机数种子 
		while (1)
		{
			bigrand(p_1, k);				// k <= p-2
			if (compare(k, one) < 0)			// x >= 1
				continue;
			egcd(k, p_1, flag);				// 计算两个大数的最大公约数			flag = gcd(k,p_1)
			if (compare(flag, one) == 0)
				break;
		}

		// c1 = g^k mod p
		powmod(g, k, p, c1);

		// c2 = m * y^k mod p
		powmod2(m, one, y, k, p, c2);

		printf("\n>>【密文】：\n  c1 = ");
		cotnum(c1, stdout);
		printf("\n  c2 = ");
		cotnum(c2, stdout);
	}

	//************************ ElGamal 脱密变换 ************************//
	{
		// 从密文恢复相应的明文 de_m
		copy(c1, flag);						// flag = c1
		xgcd(flag, p, flag, flag, flag);			// 计算两个大数的扩展最大公约数，也可以用来计算模逆			flag = flag^(-1) mod p	即 flag = c1^(-1) mod p
		powmod(flag, x, p, c1);					// c1 = flag^x mod p		即 c1 = (c1^(-1))^x mod p
		powmod(c2, one, p, c2);					// c2 = c2 mod p
		powmod2(c1, one, c2, one, p, de_m);			// de_m = c1*c2 mod p	即 de_m = c2 * (c1^(-1))^x mod p
		printf("\n>>【从密文恢复得到的明文】：\n  de_m = ");
		cotnum(de_m, stdout);
		printf("\n---------------------------------------------------------------------------------\n");
	}

	//************************ ElGamal 签名算法 ************************//
	{
		// 随机选取整数 k ，1 <= k <= p-2 , (k,p-1) = 1
		irand((unsigned)time(NULL));				// 使用当前时间作为随机数种子 
		while (1)
		{
			bigrand(p_1, k);				// k <= p-2
			if (compare(k, one) < 0)			// x >= 1
				continue;
			egcd(k, p_1, flag);				// 计算两个大数的最大公约数			flag = gcd(k,p_1)
			if (compare(flag, one) == 0)
				break;
		}

		// r = g^k mod p
		powmod(g, k, p, r);

		copy(k, flag);						// flag = k
		xgcd(flag, p_1, flag, flag, flag);			// 计算两个大数的扩展最大公约数，也可以用来计算模逆			flag = flag^(-1) mod p-1	即 flag = k^(-1) mod p-1
		multiply(r, x, temp);					// 两个大数相乘			temp = r * x
		negify(temp, temp);					// 大数取负号			temp = -temp
		add(m, temp, temp);					// 两个大数相加			temp = m + (-temp)	即 temp = m - r * x

		// s = k^(-1) * (m - rx) mod p-1
		multiply(flag, temp, temp);
		powmod(temp, one, p_1, s);
		if(compare(s, mirvar(0)) < 0)
			add(s, p_1, s);

		printf("\n>>【数字签名】：\n  r = ");
		cotnum(r, stdout);
		printf("\n  s = ");
		cotnum(s, stdout);
	}
	
	//************************ ElGamal 验证算法 ************************//
	{
		// flag = y^r * r^s mod p
		powmod2(y, r, r, s, p, flag);

		// temp = g^m mod p
		powmod(g, m, p, temp);

		printf("\n>>【验证结果】：\n  y^r * r^s mod p = ");
		cotnum(flag, stdout);
		printf("\n  g^m mod p =       ");
		cotnum(temp, stdout);

		if (compare(flag, temp) == 0)
			printf("\n【签名有效！】\n\n");
		else
			printf("\n【签名无效！】\n\n");
	}

	mirexit();							// 在MIRACL的当前实例之后清理，并释放所有内部变量。随后调用mirsys将重新初始化MIRACL系统（清除MIRACL系统，释放所有内部变量）
	system("pause");
	return 0;
}
